package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/pr60x"
)

var (
	_ resource.Resource                = &pr60xPortSettingsResource{}
	_ resource.ResourceWithImportState = &pr60xPortSettingsResource{}
)

type pr60xPortSettingsResource struct {
	client *pr60x.Client
}

func NewPR60XPortSettingsResource() resource.Resource { return &pr60xPortSettingsResource{} }

type pr60xPortSettingsModel struct {
	Port           types.String `tfsdk:"port"`
	EEE            types.Bool   `tfsdk:"energy_efficient_ethernet"`
	FlowControl    types.Bool   `tfsdk:"flow_control"`
	LinkSpeed      types.String `tfsdk:"link_speed"`
	RxCompensation types.String `tfsdk:"rx_compensation"`
	PortType       types.String `tfsdk:"port_type"`
}

func (r *pr60xPortSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_port_settings"
}

func (r *pr60xPortSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Physical-layer settings for one router port: EEE, flow control, link speed and receive " +
			"compensation.\n\n" +
			"**This mostly declares state rather than changing it, and that is the point.** Every port ships " +
			"with EEE off, flow control off and speed on auto, which is the right configuration - what is not " +
			"right is that nothing would notice if a firmware upgrade changed it. EEE in particular fails " +
			"quietly: it powers the PHY down between frames, and its wake latency shows up as jitter or link " +
			"flaps that nobody would trace back to a power-saving toggle.\n\n" +
			"**The port layout is not uniform**, which matters when reading the supported-speed list:\n\n" +
			"* `wan1`, `lan1`-`lan3` - gigabit copper, settable to auto / 100 Mbps / 1 Gbps.\n" +
			"* `lan4` - **SFP+**, settable to auto / 10 Gbps Force / 1 Gbps / 1 Gbps Force. There is no " +
			"2.5 or 5 Gbps step on this port.\n" +
			"* `lan5` - multi-gig copper, the only port offering 2.5 Gbps and 5 Gbps.\n\n" +
			"Note the router's alarm log claims the WAN port supports 2.5 Gbps. Its own settable list here " +
			"stops at 1 Gbps, and the two disagree; this list is the one that governs what you can set.",
		Attributes: map[string]schema.Attribute{
			"port": schema.StringAttribute{
				Required:    true,
				Description: "Port name as the device uses it: `wan1`, or `lan1` through `lan5`. Not an index.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"energy_efficient_ethernet": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "802.3az EEE. Defaults to false, matching the shipped state and the right answer " +
					"for a link carrying cluster traffic - the power saved is negligible next to the wake " +
					"latency it introduces. `lan4` does not support it at all and will reject true.",
			},
			"flow_control": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "802.3x PAUSE. Defaults to false, which is the shipped state and, on this network, " +
					"the measured-correct one: an oversubscription test that saturated a node's link and " +
					"produced 33,000 TCP retransmits recorded ZERO receive overruns on that node, so there is " +
					"nothing for PAUSE to signal. Enabling it trades drops for head-of-line blocking, because " +
					"PAUSE stops an entire link rather than one flow.",
			},
			"link_speed": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("auto"),
				Description: "Configured speed, not the negotiated result. `auto` unless you have a specific " +
					"reason - forcing a speed also disables autonegotiation, and a forced/auto mismatch with " +
					"the link partner produces a duplex mismatch that presents as a slow link rather than a " +
					"broken one. Valid values differ per port; see the resource description.",
			},
			"rx_compensation": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString("default"),
				Description: "Undocumented receive-path tuning, `default` or `enhanced`. The router ships " +
					"`lan4` and `lan5` on `enhanced` and the gigabit copper ports on `default`, so the " +
					"defaults here are NOT uniform - declare what the port actually has or every plan shows " +
					"a diff. Worth knowing about on `lan4`, which is the SFP+ uplink and the one port on this " +
					"router accumulating receive errors.",
			},
			"port_type": schema.StringAttribute{
				Computed:    true,
				Description: "`copper` or `sfp_plus`, as the device reports it. Read-only.",
			},
		},
	}
}

func (r *pr60xPortSettingsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.PR60X == nil {
		resp.Diagnostics.AddError("PR60X not configured",
			"This resource manages the router. Add a `pr60x` block to the provider, or set PR60X_PASSWORD.")
		return
	}
	r.client = c.PR60X
}

func (m *pr60xPortSettingsModel) fromWire(p pr60x.PortSettings) {
	m.Port = types.StringValue(p.Port)
	m.EEE = types.BoolValue(p.EnableEEE == 1)
	m.FlowControl = types.BoolValue(p.EnableFlowControl == 1)
	m.LinkSpeed = types.StringValue(p.LinkSpeed)
	m.RxCompensation = types.StringValue(p.RxCompensation)
	m.PortType = types.StringValue(p.Type)
}

func (r *pr60xPortSettingsResource) apply(plan *pr60xPortSettingsModel, diags diagSink) {
	name := plan.Port.ValueString()
	cur, err := r.client.GetPortSetting(name)
	if err != nil {
		diags.AddError("Could not read the port", err.Error())
		return
	}
	if cur == nil {
		diags.AddError("No such port",
			"The router has no port named "+name+". Valid names are wan1 and lan1 through lan5.")
		return
	}
	if plan.EEE.ValueBool() && cur.SupportEEE == 0 {
		diags.AddError("That port does not support EEE",
			"Port "+name+" reports supportEEE=0, so energy_efficient_ethernet cannot be enabled on it. "+
				"On this router that is the SFP+ port.")
		return
	}

	// Read-modify-write the WHOLE object. A partial payload is accepted and
	// silently ignored by this firmware - see SetPortSettings.
	want := *cur
	want.EnableEEE = boolToInt(plan.EEE.ValueBool())
	want.EnableFlowControl = boolToInt(plan.FlowControl.ValueBool())
	want.LinkSpeed = plan.LinkSpeed.ValueString()
	want.RxCompensation = plan.RxCompensation.ValueString()

	if err := r.client.SetPortSettings(want); err != nil {
		diags.AddError("Could not set the port settings", err.Error())
		return
	}
	got, err := r.client.GetPortSetting(name)
	if err != nil {
		diags.AddError("Could not read back the port settings", err.Error())
		return
	}
	plan.fromWire(*got)
}

func (r *pr60xPortSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pr60xPortSettingsModel
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

func (r *pr60xPortSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pr60xPortSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetPortSetting(state.Port.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Could not read the port settings", err.Error())
		return
	}
	if got == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *pr60xPortSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan pr60xPortSettingsModel
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

// Delete DOES NOTHING TO THE DEVICE, deliberately.
//
// Every value this resource manages is a physical-layer setting on a port that
// is probably carrying traffic. There is no "unconfigured" state to return to
// that is safer than what is already running, and forcing the shipped defaults
// on destroy would renegotiate a live link as a side effect of a config
// cleanup. Removing the resource stops Terraform tracking the port.
func (r *pr60xPortSettingsResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState takes the port name:
//
//	terraform import netgear_pr60x_port_settings.lan4 lan4
func (r *pr60xPortSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetPortSetting(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Could not read the port settings", err.Error())
		return
	}
	if got == nil {
		resp.Diagnostics.AddError("No such port",
			"The router has no port named "+req.ID+". Valid names are wan1 and lan1 through lan5.")
		return
	}
	var state pr60xPortSettingsModel
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), got.Port)...)
}
