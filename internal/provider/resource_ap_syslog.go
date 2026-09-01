package provider

import (
	"context"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/wax630e"
)

var (
	_ resource.Resource                = &apSyslogResource{}
	_ resource.ResourceWithImportState = &apSyslogResource{}
)

type apSyslogResource struct {
	client *wax630e.Client
}

func NewAPSyslogResource() resource.Resource { return &apSyslogResource{} }

type apSyslogModel struct {
	Host    types.String `tfsdk:"host"`
	Port    types.Int64  `tfsdk:"port"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func (r *apSyslogResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wax630e_syslog"
}

func (r *apSyslogResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Remote syslog on the access point.\n\n" +
			"A settings singleton, not a list: the AP holds exactly one collector, so this resource overwrites " +
			"whatever is there rather than adding an entry. Destroying it disables remote logging and leaves the " +
			"address in place, which is what the firmware itself does.\n\n" +
			"The address and the enable flag are stored independently, so an AP can sit with a perfectly good " +
			"collector address and `syslogStatus` 0, silently sending nothing. That is the state this one was " +
			"found in. Managing both fields together is the point of the resource.\n\n" +
			"The AP emits RFC3164 (BSD) syslog; a collector defaulting to RFC5424 drops every packet with a " +
			"parse error rather than reporting a problem.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Required:    true,
				Description: "Collector address.",
			},
			"port": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default:     int64default.StaticInt64(514),
				Description: "UDP port of the collector.",
			},
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether the AP actually ships logs. Ships disabled.",
			},
		},
	}
}

func (r *apSyslogResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.WAX630E == nil {
		resp.Diagnostics.AddError("WAX630E not configured",
			"This resource manages the access point. Add a `wax630e` block to the provider, or set WAX630E_PASSWORD.")
		return
	}
	r.client = c.WAX630E
}

func (m apSyslogModel) toSettings() wax630e.SyslogSettings {
	status := "0"
	if m.Enabled.ValueBool() {
		status = "1"
	}
	// Every field goes over the wire as a string; the firmware rejects real
	// JSON numbers for the port.
	return wax630e.SyslogSettings{
		Status: status,
		IP:     m.Host.ValueString(),
		Port:   strconv.FormatInt(m.Port.ValueInt64(), 10),
	}
}

func applyAPSyslog(dst *apSyslogModel, s wax630e.SyslogSettings) {
	dst.Host = types.StringValue(s.IP)
	dst.Enabled = types.BoolValue(s.Status == "1")
	port, err := strconv.ParseInt(s.Port, 10, 64)
	if err != nil {
		port = 514
	}
	dst.Port = types.Int64Value(port)
}

func (r *apSyslogResource) apply(plan *apSyslogModel, diags interface {
	AddError(string, string)
}) {
	if err := r.client.SetSyslog(plan.toSettings()); err != nil {
		diags.AddError("Could not set syslog on the access point", err.Error())
		return
	}
	got, err := r.client.GetSyslog()
	if err != nil {
		diags.AddError("Could not read back syslog settings", err.Error())
		return
	}
	applyAPSyslog(plan, got)
}

func (r *apSyslogResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apSyslogModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *apSyslogResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apSyslogModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetSyslog()
	if err != nil {
		resp.Diagnostics.AddError("Could not read syslog settings", err.Error())
		return
	}
	applyAPSyslog(&state, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *apSyslogResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan apSyslogModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete turns remote logging off but leaves the collector address alone. The
// firmware keeps the address across a disable, and blanking it would only make
// re-enabling harder.
func (r *apSyslogResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state apSyslogModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Enabled = types.BoolValue(false)
	if err := r.client.SetSyslog(state.toSettings()); err != nil {
		resp.Diagnostics.AddError("Could not disable syslog on the access point", err.Error())
	}
}

func (r *apSyslogResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetSyslog()
	if err != nil {
		resp.Diagnostics.AddError("Could not read syslog settings", err.Error())
		return
	}
	var state apSyslogModel
	applyAPSyslog(&state, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
