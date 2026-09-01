package provider

import (
	"netgear-tools/internal/pr60x"

	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &remoteSyslogResource{}
	_ resource.ResourceWithImportState = &remoteSyslogResource{}
)

type remoteSyslogResource struct {
	client *pr60x.Client
}

func NewRemoteSyslogResource() resource.Resource {
	return &remoteSyslogResource{}
}

type remoteSyslogModel struct {
	Enabled    types.Bool   `tfsdk:"enabled"`
	ServerIP   types.String `tfsdk:"server_ip_address"`
	ServerPort types.Int64  `tfsdk:"server_port"`
}

func (r *remoteSyslogResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_remote_syslog"
}

func (r *remoteSyslogResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Ships the router's system log to an external syslog collector over UDP.\n\n" +
			"Worth turning on: an appliance's log is otherwise only visible by logging into its web UI, and it is " +
			"the only place events like an uncontrolled shutdown, a WAN flap or a link renegotiation are recorded. " +
			"Point it at any UDP syslog listener - a Promtail/Alloy syslog receiver, rsyslog, or similar.\n\n" +
			"This is a settings singleton, so there is only ever one of it. Destroying the resource disables " +
			"forwarding rather than deleting anything.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
			"server_ip_address": schema.StringAttribute{
				Required:    true,
				Description: "Address of the syslog collector.",
			},
			"server_port": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(514),
				Description: "UDP port of the collector. The device speaks UDP syslog only.",
			},
		},
	}
}

func (r *remoteSyslogResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*pr60x.Client)
}

func (m remoteSyslogModel) toAPI() pr60x.RemoteSyslog {
	enabled := int64(0)
	if m.Enabled.ValueBool() {
		enabled = 1
	}
	return pr60x.RemoteSyslog{
		Enabled:         enabled,
		ServerIPAddress: m.ServerIP.ValueString(),
		ServerPort:      m.ServerPort.ValueInt64(),
	}
}

func applyRemoteSyslog(dst *remoteSyslogModel, src *pr60x.RemoteSyslog) {
	dst.Enabled = types.BoolValue(src.Enabled != 0)
	dst.ServerIP = types.StringValue(src.ServerIPAddress)
	dst.ServerPort = types.Int64Value(src.ServerPort)
}

func (r *remoteSyslogResource) write(plan *remoteSyslogModel, resp interface {
	AddError(string, string)
}) {
	if err := r.client.SetRemoteSyslog(plan.toAPI()); err != nil {
		resp.AddError("Could not set remote syslog", err.Error())
		return
	}
	got, err := r.client.GetRemoteSyslog()
	if err != nil {
		resp.AddError("Could not read back remote syslog", err.Error())
		return
	}
	applyRemoteSyslog(plan, got)
}

func (r *remoteSyslogResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan remoteSyslogModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *remoteSyslogResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state remoteSyslogModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetRemoteSyslog()
	if err != nil {
		resp.Diagnostics.AddError("Could not read remote syslog", err.Error())
		return
	}
	applyRemoteSyslog(&state, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *remoteSyslogResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan remoteSyslogModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(&plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete disables forwarding rather than deleting a record - there is no
// record to delete, only a setting to turn off. The collector address is left
// in place so re-enabling is a one-field change.
func (r *remoteSyslogResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state remoteSyslogModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	off := state.toAPI()
	off.Enabled = 0
	if err := r.client.SetRemoteSyslog(off); err != nil {
		resp.Diagnostics.AddError("Could not disable remote syslog", err.Error())
	}
}

func (r *remoteSyslogResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetRemoteSyslog()
	if err != nil {
		resp.Diagnostics.AddError("Could not read remote syslog", err.Error())
		return
	}
	var state remoteSyslogModel
	applyRemoteSyslog(&state, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
