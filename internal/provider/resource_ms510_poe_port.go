package provider

import (
	"context"
	"fmt"
	"strconv"

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
	Port            types.Int64 `tfsdk:"port"`
	Enabled         types.Bool  `tfsdk:"enabled"`
	Priority        types.Int64 `tfsdk:"priority"`
	PowerLimitWatts types.Int64 `tfsdk:"power_limit_watts"`
	PowerLimitMode  types.Int64 `tfsdk:"power_limit_mode"`
	DetectMode      types.Int64 `tfsdk:"detect_mode"`
	DetectionDelay  types.Int64 `tfsdk:"detection_delay"`
}

func (r *ms510PoEPortResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_poe_port"
}

func (r *ms510PoEPortResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "PoE settings for one port on the MS510TXUP.\n\n" +
			"**PORTS 1-4 POWER THE CLUSTER.** The four Raspberry Pi 5 nodes run entirely off PoE from this " +
			"switch. Setting `enabled = false` on one of those ports hard-cuts power to a Kubernetes node " +
			"with no shutdown - it is the plug being pulled, not a drain. Terraform will do it without " +
			"comment if you ask, so do not ask by accident.\n\n" +
			"Mostly this resource exists to DECLARE state rather than change it. The switch ships with every " +
			"port enabled at the maximum limit and equal priority, which is fine - what is not fine is that " +
			"a firmware upgrade can reset it (this switch has cleared its syslog host and SNTP server that " +
			"way before) and a PoE port quietly back at a lower limit presents as a node that reboots under " +
			"load for no visible reason.\n\n" +
			"`priority` is the one setting worth thinking about rather than just pinning: when the chassis " +
			"budget is exceeded the switch sheds the LOWEST-priority ports first. Leaving the cluster nodes " +
			"at the same priority as a camera means the shedding order is arbitrary.",
		Attributes: map[string]schema.Attribute{
			"port": schema.Int64Attribute{
				Required: true,
				Description: "Front-panel port number, 1-8. Only the eight 2.5G ports deliver power; the " +
					"two 10G uplinks (9 and 10) have no PoE and are not valid here.",
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
				Description: "Shedding priority when the chassis budget is exceeded; the switch drops the " +
					"lowest priority first. 0 is the highest (critical). The switch ships every port at 0, " +
					"so by default the shedding order is undefined.",
			},
			"power_limit_watts": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(60),
				Description: "Per-port ceiling in WATTS, 3-60. The device speaks milliwatts as a string; " +
					"this converts. A powered device that reaches this limit is cut off, which looks like an " +
					"unexplained reboot rather than a power problem - so a limit set tight to 'be safe' is " +
					"the more dangerous choice here.",
			},
			"power_limit_mode": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Default:  int64default.StaticInt64(1),
				Description: "How the ceiling is derived: the switch's own encoding, where 1 is the shipped " +
					"value (limit taken from the negotiated class). Left as an opaque number because the " +
					"firmware documents no names for it.",
			},
			"detect_mode": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Powered-device detection mode, switch encoding. 0 is the shipped value.",
			},
			"detection_delay": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int64default.StaticInt64(0),
				Description: "Seconds to wait before detecting a powered device. 0 is the shipped value.",
			},
		},
	}
}

func (r *ms510PoEPortResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if c := ms510Client(req.ProviderData, &resp.Diagnostics, "PoE"); c != nil {
		r.client = c
	}
}

// get returns one port's row, or nil when the port has no PoE.
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
	m.PowerLimitWatts = types.Int64Value(int64(ms510txup.PoEMilliwatts(p.AdminPower) / 1000))
	m.PowerLimitMode = types.Int64Value(int64(p.PowerLimitMode))
	m.DetectMode = types.Int64Value(int64(p.DetectMode))
	m.DetectionDelay = types.Int64Value(int64(p.DetectionDelay))
}

// apply writes the row and reads it back, because this firmware answers
// save_success for writes it discarded - see SetIGMPSnoopingVLAN for the case
// that established that.
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
				"9 and 10 are the 10G uplinks.", port))
		return
	}

	state := 0
	if plan.Enabled.ValueBool() {
		state = 1
	}
	// PowerMode and the flags this resource does not model are carried over
	// from the live row rather than defaulted, so a field the firmware has and
	// Terraform does not cannot be silently cleared by an apply.
	want := *cur
	want.State = state
	want.Priority = int(plan.Priority.ValueInt64())
	want.AdminPower = strconv.Itoa(int(plan.PowerLimitWatts.ValueInt64()) * 1000)
	want.PowerLimitMode = int(plan.PowerLimitMode.ValueInt64())
	want.DetectMode = int(plan.DetectMode.ValueInt64())
	want.DetectionDelay = int(plan.DetectionDelay.ValueInt64())

	if err := r.client.SetPoEPort(port, want); err != nil {
		diags.AddError("Could not set the PoE port", err.Error())
		return
	}
	got, err := r.get(port)
	if err != nil {
		diags.AddError("Could not read back the PoE port", err.Error())
		return
	}
	if got == nil {
		diags.AddError("The PoE port vanished after the write",
			fmt.Sprintf("Port %d had a PoE row before the write and does not after.", port))
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
// The obvious inverse of "manage this PoE port" would be to return it to the
// shipped state, but the shipped state is "enabled" and the plausible-looking
// alternative - disabling it - would power off a cluster node as a side effect
// of a `terraform destroy` or a resource being removed from the config. That
// is not a trade worth making for tidiness. Removing the resource stops
// Terraform tracking the port; the port keeps running.
func (r *ms510PoEPortResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState takes the port number:
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
	state := ms510PoEPortModel{Port: types.Int64Value(int64(port))}
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
