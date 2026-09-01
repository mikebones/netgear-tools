package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &switchSyslogServerResource{}
	_ resource.ResourceWithImportState = &switchSyslogServerResource{}
)

type switchSyslogServerResource struct {
	client interface {
		Get(string, any) error
		Post(string, any, any) error
	}
}

func NewSwitchSyslogServerResource() resource.Resource { return &switchSyslogServerResource{} }

type switchSyslogServerModel struct {
	Host        types.String `tfsdk:"host"`
	Port        types.Int64  `tfsdk:"port"`
	AddressType types.Int64  `tfsdk:"address_type"`
	Severity    types.Int64  `tfsdk:"severity"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func (r *switchSyslogServerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_syslog_server"
}

func (r *switchSyslogServerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A remote syslog destination on the switch.\n\n" +
			"Creating one also turns on the switch's global remote-logging flag, which ships disabled - a server " +
			"entry alone does nothing without it, and that is an easy hour to lose.\n\n" +
			"The switch speaks RFC3164 (BSD) syslog. A collector defaulting to RFC5424 will drop every packet " +
			"with a parse error rather than reporting a problem.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Required:      true,
				Description:   "Collector address.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"port": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default:     int64default.StaticInt64(514),
				Description: "UDP port of the collector.",
			},
			"address_type": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default:     int64default.StaticInt64(0),
				Description: "Address family as the firmware encodes it: 0 IPv4, 1 IPv6, 2 hostname.",
			},
			"severity": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default: int64default.StaticInt64(6),
				Description: "Severity threshold, standard syslog numbering: 0 emergency through 7 debug. " +
					"6 (informational) is a sensible default; these switches are quiet either way.",
			},
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default: booldefault.StaticBool(true),
			},
		},
	}
}

func (r *switchSyslogServerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.XS508TM == nil {
		resp.Diagnostics.AddError("XS508TM not configured",
			"This resource manages the switch. Add an `xs508tm` block to the provider, or set XS508TM_PASSWORD.")
		return
	}
	r.client = c.XS508TM
}

type syslogEntry struct {
	Host   string `json:"host"`
	Type   int64  `json:"type"`
	Port   int64  `json:"port"`
	Sev    int64  `json:"sev"`
	Status int64  `json:"status"`
}

type syslogList struct {
	Servers []syslogEntry `json:"server_log_cfg"`
}

func (m switchSyslogServerModel) toEntry() syslogEntry {
	status := int64(0)
	if m.Enabled.ValueBool() {
		status = 1
	}
	return syslogEntry{
		Host: m.Host.ValueString(), Type: m.AddressType.ValueInt64(),
		Port: m.Port.ValueInt64(), Sev: m.Severity.ValueInt64(), Status: status,
	}
}

func applySyslogEntry(dst *switchSyslogServerModel, e syslogEntry) {
	dst.Host = types.StringValue(e.Host)
	dst.AddressType = types.Int64Value(e.Type)
	dst.Port = types.Int64Value(e.Port)
	dst.Severity = types.Int64Value(e.Sev)
	dst.Enabled = types.BoolValue(e.Status != 0)
}

func (r *switchSyslogServerResource) find(host string) (*syslogEntry, error) {
	var list syslogList
	if err := r.client.Get("server_log_cfg", &list); err != nil {
		return nil, err
	}
	for i := range list.Servers {
		if list.Servers[i].Host == host {
			return &list.Servers[i], nil
		}
	}
	return nil, nil
}

// enableGlobal flips the switch-wide remote-logging admin flag. Server entries
// are inert without it.
func (r *switchSyslogServerResource) enableGlobal(on bool) error {
	v := 0
	if on {
		v = 1
	}
	return r.client.Post("server_log_global_cfg",
		map[string]any{"server_log_global_cfg": map[string]any{"admin": v}}, nil)
}

func (r *switchSyslogServerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan switchSyslogServerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if err := r.enableGlobal(true); err != nil {
		resp.Diagnostics.AddError("Could not enable remote logging", err.Error())
		return
	}

	// The POST body is an ARRAY. A bare object is rejected with errCode 175,
	// which is also what a duplicate host returns - so check first and give a
	// useful message rather than surfacing an opaque code.
	if existing, err := r.find(plan.Host.ValueString()); err != nil {
		resp.Diagnostics.AddError("Could not list syslog servers", err.Error())
		return
	} else if existing != nil {
		resp.Diagnostics.AddError("Syslog server already exists",
			fmt.Sprintf("The switch already has an entry for %q. Import it with: "+
				"terraform import netgear_xs508tm_syslog_server.<name> %s",
				plan.Host.ValueString(), plan.Host.ValueString()))
		return
	}

	if err := r.client.Post("server_log_cfg", []syslogEntry{plan.toEntry()}, nil); err != nil {
		resp.Diagnostics.AddError("Could not add syslog server", err.Error())
		return
	}
	got, err := r.find(plan.Host.ValueString())
	if err != nil || got == nil {
		resp.Diagnostics.AddError("Syslog server was not created",
			"The switch accepted the request but the entry is absent on read-back.")
		return
	}
	applySyslogEntry(&plan, *got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *switchSyslogServerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state switchSyslogServerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.find(state.Host.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read syslog servers", err.Error())
		return
	}
	if got == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	applySyslogEntry(&state, *got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update replaces the entry: this firmware's add path rejects a host it
// already knows (errCode 175), so a change is delete-then-add.
func (r *switchSyslogServerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan switchSyslogServerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.deleteHost(plan.Host.ValueString()); err != nil {
		resp.Diagnostics.AddError("Could not remove the old syslog entry before rewriting it", err.Error())
		return
	}
	if err := r.client.Post("server_log_cfg", []syslogEntry{plan.toEntry()}, nil); err != nil {
		resp.Diagnostics.AddError("Could not update syslog server", err.Error())
		return
	}
	got, err := r.find(plan.Host.ValueString())
	if err != nil || got == nil {
		resp.Diagnostics.AddError("Syslog server missing after update",
			"The entry was removed but the replacement did not appear; check the switch.")
		return
	}
	applySyslogEntry(&plan, *got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *switchSyslogServerResource) deleteHost(host string) error {
	// The UI's delete path posts a list of {host} objects to the same route.
	return r.client.Post("server_log_cfg",
		map[string]any{"server_log_cfg": []map[string]string{{"host": host}}, "from": "delete"}, nil)
}

func (r *switchSyslogServerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state switchSyslogServerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.deleteHost(state.Host.ValueString()); err != nil {
		resp.Diagnostics.AddError("Could not delete syslog server", err.Error())
	}
	// The global flag is left on deliberately: other collectors may still be
	// configured, and turning it off would silently stop them too.
}

func (r *switchSyslogServerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host"), req.ID)...)
}
