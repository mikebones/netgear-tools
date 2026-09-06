package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510PoEPortResource{}
	_ resource.ResourceWithImportState = &ms510PoEPortResource{}
)

type ms510PoEPortResource struct {
	client *ms510txup.Client
}

func NewMS510PoEPortResource() resource.Resource { return &ms510PoEPortResource{} }

type ms510PoEPortModel struct {
	Port           types.Int64  `tfsdk:"port"`
	Enabled        types.Bool   `tfsdk:"enabled"`
	Priority       types.Int64  `tfsdk:"priority"`
	PowerMode      types.Int64  `tfsdk:"power_mode"`
	DetectMode     types.Int64  `tfsdk:"detect_mode"`
	DetectionDelay types.Bool   `tfsdk:"longer_detection_time"`
	PowerWatts     types.Int64  `tfsdk:"power_watts"`
	Class          types.String `tfsdk:"class"`
	Status         types.String `tfsdk:"status"`
}

func (r *ms510PoEPortResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_poe_port"
}

func (r *ms510PoEPortResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "PoE settings for one port on the MS510TXUP.\n\n" +
			"**PORTS 1-4 POWER THE CLUSTER.** The four Raspberry Pi 5 nodes run entirely off PoE from this " +
			"switch at 6-11 W each. Setting `enabled = false` on one of those hard-cuts power to a Kubernetes " +
			"node with no shutdown - it is the plug being pulled, not a drain.\n\n" +
			"**`priority` is the setting actually worth changing here.** When the PoE budget is exceeded the " +
			"switch sheds the LOWEST priority ports first, and this switch ships every port at `0` (Low) - so " +
			"out of the box the cluster nodes are in the first group to be dropped, tied with everything else. " +
			"There is 295 W of budget against 47 W drawn today, so nothing sheds now; the ordering matters the " +
			"day a high-draw device is added.\n\n" +
			"Note there is no per-port power ceiling on this model: Max Power is derived from the negotiated " +
			"class and is read-only, which is why no such attribute exists here.",
		Attributes: map[string]schema.Attribute{
			"port": schema.Int64Attribute{
				Required: true,
				Description: "Front-panel port number, 1-8. Only the eight 2.5G ports deliver power; 9 and 10 " +
					"are SFP+ uplinks with no PoE. Given 1-based as printed on the chassis - the device's own " +
					"API is zero-based, and the client converts.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				Description: "Whether the port delivers power. FALSE CUTS POWER IMMEDIATELY - on ports 1-4 " +
					"that powers off a cluster node without a shutdown.",
			},
			"priority": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
				Description: "Shedding priority: **0 Low, 1 Medium, 2 High, 3 Critical**. Higher survives " +
					"longer - the switch drops Low first. The device default is 0 for every port, which is " +
					"why this is worth setting deliberately rather than leaving.",
			},
			"power_mode": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(6),
				Description: "PoE standard to offer: 0 802.3af, 1 Legacy, 2 Pre-802.3at, 3 802.3at, " +
					"4 pre-802.3bt, 5 pre-802.3bt-lldp, 6 802.3bt-type3. This switch ships every port at 6, " +
					"which negotiates down for older devices - lowering it caps what a device may draw.",
			},
			"detect_mode": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(0),
				Description: "Powered-device detection: 0 IEEE 802, 1 4ptdot3af+legacy, 2 Legacy. Leave at 0 " +
					"unless a device genuinely fails to be detected; the legacy modes relax the signature " +
					"check and can energise something that is not a PD.",
			},
			"longer_detection_time": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(false),
				Description: "Wait longer before declaring a powered device present. Off by default; useful " +
					"only for devices that are slow to present a valid signature.",
			},
			"power_watts": schema.Int64Attribute{
				Computed: true,
				Description: "Power currently delivered, in whole watts. Read-only observation, not a " +
					"setting - use the ms510txup_poe_port_power_watts metric for anything time-series.",
			},
			"class": schema.StringAttribute{
				Computed:    true,
				Description: "Negotiated 802.3af/at/bt class as the device reports it. Read-only.",
			},
			"status": schema.StringAttribute{
				Computed: true,
				Description: "`Delivering`, `Searching`, or a fault string. Read-only. `Searching` means " +
					"enabled but nothing detected - an unplugged or dead powered device.",
			},
		},
	}
}

func (r *ms510PoEPortResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if c := ms510Client(req.ProviderData, &resp.Diagnostics, "PoE"); c != nil {
		r.client = c
	}
}

func (r *ms510PoEPortResource) get(port int) (*ms510txup.PoEPort, error) {
	cfg, err := r.client.GetPoE()
	if err != nil {
		return nil, err
	}
	if port < 1 || port > len(cfg.Ports) {
		return nil, nil
	}
	return &cfg.Ports[port-1], nil
}

func (m *ms510PoEPortModel) fromWire(p ms510txup.PoEPort) {
	m.Enabled = types.BoolValue(p.State == 1)
	m.Priority = types.Int64Value(int64(p.Priority))
	m.PowerMode = types.Int64Value(int64(p.PowerMode))
	m.DetectMode = types.Int64Value(int64(p.DetectMode))
	m.DetectionDelay = types.BoolValue(p.DetectionDelay == 1)
	m.PowerWatts = types.Int64Value(int64(ms510txup.PoEMilliwatts(p.Power) / 1000))
	m.Class = types.StringValue(ms510txup.PoELangValue(p.Class))
	m.Status = types.StringValue(ms510txup.PoELangValue(p.Status))
}

// apply writes the row and reads it back. This firmware answers save_success
// for writes it discarded - the missing zero-based selEntry did exactly that
// for a long time - so the read-back is the only evidence a write took.
func (r *ms510PoEPortResource) apply(plan *ms510PoEPortModel, diags diagSink) {
	port := int(plan.Port.ValueInt64())
	cur, err := r.get(port)
	if err != nil {
		diags.AddError("Could not read the PoE port", err.Error())
		return
	}
	if cur == nil {
		diags.AddError("That port has no PoE",
			fmt.Sprintf("Port %d is not PoE-capable on this switch. Only ports 1-8 deliver power; "+
				"9 and 10 are the SFP+ uplinks.", port))
		return
	}

	// Carry the live row forward and change only what this resource models, so
	// a field the firmware has and Terraform does not cannot be cleared.
	want := *cur
	want.State = boolToInt(plan.Enabled.ValueBool())
	want.Priority = int(plan.Priority.ValueInt64())
	want.PowerMode = int(plan.PowerMode.ValueInt64())
	want.DetectMode = int(plan.DetectMode.ValueInt64())
	want.DetectionDelay = boolToInt(plan.DetectionDelay.ValueBool())

	if err := r.client.SetPoEPort(port, want); err != nil {
		diags.AddError("Could not set the PoE port", err.Error())
		return
	}
	got, err := r.get(port)
	if err != nil {
		diags.AddError("Could not read back the PoE port", err.Error())
		return
	}
	plan.fromWire(*got)
}

func (r *ms510PoEPortResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510PoEPortModel
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

func (r *ms510PoEPortResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510PoEPortModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.get(int(state.Port.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Could not read the PoE port", err.Error())
		return
	}
	if got == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510PoEPortResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510PoEPortModel
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
// The tidy inverse would be returning the port to its shipped state, but the
// shipped state is "enabled at Low priority" and the plausible-looking
// alternative - disabling it - would power off a cluster node as a side effect
// of a resource being removed from the config. Removing the resource stops
// Terraform tracking the port; the port keeps running.
func (r *ms510PoEPortResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState takes the 1-based port number:
//
//	terraform import netgear_ms510txup_poe_port.rp5_0 1
func (r *ms510PoEPortResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	port, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			"Import this resource with the port number, for example "+
				"`terraform import netgear_ms510txup_poe_port.rp5_0 1`. Got: "+req.ID)
		return
	}
	got, err := r.get(port)
	if err != nil {
		resp.Diagnostics.AddError("Could not read the PoE port", err.Error())
		return
	}
	if got == nil {
		resp.Diagnostics.AddError("That port has no PoE",
			fmt.Sprintf("Port %d is not PoE-capable on this switch.", port))
		return
	}
	var state ms510PoEPortModel
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), port)...)
}
