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

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510SyslogServerResource{}
	_ resource.ResourceWithImportState = &ms510SyslogServerResource{}
)

type ms510SyslogServerResource struct {
	client *ms510txup.Client
}

func NewMS510SyslogServerResource() resource.Resource { return &ms510SyslogServerResource{} }

type ms510SyslogServerModel struct {
	Host        types.String `tfsdk:"host"`
	Port        types.Int64  `tfsdk:"port"`
	AddressType types.Int64  `tfsdk:"address_type"`
	Severity    types.Int64  `tfsdk:"severity"`
	Enabled     types.Bool   `tfsdk:"enabled"`
}

func (r *ms510SyslogServerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_syslog_server"
}

func (r *ms510SyslogServerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A remote syslog collector on the MS510TXUP.\n\n" +
			"Creating one also turns on the switch's global remote-logging flag, which ships disabled - a host " +
			"entry alone does nothing without it.\n\n" +
			"Worth knowing before you rely on the logs: this switch has no battery-backed clock and ships with " +
			"SNTP off, so unless `netgear_ms510txup_sntp` is also managing it, every message it sends will be " +
			"stamped with a date years in the past. Syslog from an unsynchronised device is worse than no " +
			"syslog, because it sorts into the wrong place and looks like history.",
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
					"6 (informational) is a sensible default.",
			},
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:     booldefault.StaticBool(true),
				Description: "The switch-wide remote logging flag. Host entries are inert without it.",
			},
		},
	}
}

func (r *ms510SyslogServerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.MS510TXUP == nil {
		resp.Diagnostics.AddError("MS510TXUP not configured",
			"This resource manages the MS510TXUP. Add an `ms510txup` block to the provider, or set MS510TXUP_PASSWORD.")
		return
	}
	r.client = c.MS510TXUP
}

func applyMS510Syslog(dst *ms510SyslogServerModel, h ms510txup.SyslogHost, globalOn bool) {
	dst.Host = types.StringValue(h.Host)
	dst.Port = types.Int64Value(int64(h.Port))
	dst.AddressType = types.Int64Value(int64(h.Type))
	dst.Severity = types.Int64Value(int64(h.Sev))
	dst.Enabled = types.BoolValue(globalOn)
}

func (r *ms510SyslogServerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510SyslogServerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	existing, err := r.client.FindSyslogHost(plan.Host.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read syslog configuration", err.Error())
		return
	}
	if existing != nil {
		resp.Diagnostics.AddError("Syslog collector already exists",
			fmt.Sprintf("The switch already has an entry for %q. Import it with: "+
				"terraform import netgear_ms510txup_syslog_server.<name> %s",
				plan.Host.ValueString(), plan.Host.ValueString()))
		return
	}

	if err := r.client.AddSyslogHost(ms510txup.SyslogHost{
		Type: int(plan.AddressType.ValueInt64()),
		Host: plan.Host.ValueString(),
		Port: int(plan.Port.ValueInt64()),
		Sev:  int(plan.Severity.ValueInt64()),
	}); err != nil {
		resp.Diagnostics.AddError("Could not add the syslog collector", err.Error())
		return
	}
	if err := r.client.SetSyslogState(plan.Enabled.ValueBool()); err != nil {
		resp.Diagnostics.AddError("Could not set the global remote-logging flag", err.Error())
		return
	}

	// This firmware answers save_success for writes it silently discarded, so
	// the read-back is the only real confirmation.
	if !r.readInto(&plan, &resp.Diagnostics, true) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// readInto refreshes the model from the device. It returns false and records a
// diagnostic on error; when mustExist is set, a missing entry is an error
// rather than a signal to drop the resource from state.
func (r *ms510SyslogServerResource) readInto(m *ms510SyslogServerModel, diags interface {
	AddError(string, string)
}, mustExist bool) bool {
	cfg, err := r.client.GetSyslog()
	if err != nil {
		diags.AddError("Could not read syslog configuration", err.Error())
		return false
	}
	for _, h := range cfg.Hosts {
		if h.Host == m.Host.ValueString() {
			applyMS510Syslog(m, h, cfg.State == 1)
			return true
		}
	}
	if mustExist {
		diags.AddError("The syslog collector was not created",
			"The switch reported success but the entry is absent on read-back. This firmware accepts "+
				"and discards field sets it does not recognise, reporting save_success either way.")
	}
	return false
}

func (r *ms510SyslogServerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510SyslogServerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readInto(&state, &resp.Diagnostics, false) {
		if !resp.Diagnostics.HasError() {
			resp.State.RemoveResource(ctx)
		}
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update: host is RequiresReplace, so only the global flag and the entry's own
// fields can change here. The firmware has no edit path for a host entry, so a
// field change is delete-then-add.
func (r *ms510SyslogServerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510SyslogServerModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteSyslogHost(plan.Host.ValueString()); err != nil {
		resp.Diagnostics.AddError("Could not remove the old syslog entry before rewriting it", err.Error())
		return
	}
	if err := r.client.AddSyslogHost(ms510txup.SyslogHost{
		Type: int(plan.AddressType.ValueInt64()),
		Host: plan.Host.ValueString(),
		Port: int(plan.Port.ValueInt64()),
		Sev:  int(plan.Severity.ValueInt64()),
	}); err != nil {
		resp.Diagnostics.AddError("Could not re-add the syslog collector", err.Error())
		return
	}
	if err := r.client.SetSyslogState(plan.Enabled.ValueBool()); err != nil {
		resp.Diagnostics.AddError("Could not set the global remote-logging flag", err.Error())
		return
	}
	if !r.readInto(&plan, &resp.Diagnostics, true) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ms510SyslogServerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ms510SyslogServerModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteSyslogHost(state.Host.ValueString()); err != nil {
		resp.Diagnostics.AddError("Could not delete the syslog collector", err.Error())
	}
	// The global flag is left on deliberately: another collector may still be
	// configured, and turning it off would silently stop that one too.
}

func (r *ms510SyslogServerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("host"), req.ID)...)
}
