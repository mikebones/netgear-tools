package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510STPPortResource{}
	_ resource.ResourceWithImportState = &ms510STPPortResource{}
)

type ms510STPPortResource struct {
	client *ms510txup.Client
}

func NewMS510STPPortResource() resource.Resource { return &ms510STPPortResource{} }

type ms510STPPortModel struct {
	Port    types.Int64  `tfsdk:"port"`
	Enabled types.Bool   `tfsdk:"enabled"`
	State   types.String `tfsdk:"state"`
}

func (r *ms510STPPortResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_stp_port"
}

func (r *ms510STPPortResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Spanning-tree participation for one port.\n\n" +
			"**Exists because a neighbour can crash this switch through STP.** A WAX630E on firmware " +
			"10.8.13.2 took this switch down twice within minutes of booting, each time needing a physical " +
			"power cycle - the AP's own release notes for 11.8.0.9 describe it as *\"STP was enabled on the " +
			"AP with incorrect Forward Delay causing intermediate switch to malfunction or crash\"*. Since " +
			"this switch also supplies PoE to all four Pi cluster nodes, that is a hard power cut of the " +
			"whole cluster.\n\n" +
			"Disabling STP on that port makes the switch immune to whatever the neighbour sends, whatever " +
			"firmware it runs. That is a better position than racing to patch the neighbour before it kills " +
			"its own uplink.\n\n" +
			"**Only ever disable this on a genuine edge port** - one host, no redundant path. It is what " +
			"portfast/edge configuration amounts to. On a port reaching another switch, STP is the only " +
			"thing standing between this network and a broadcast storm, and turning it off there is how you " +
			"get one.",
		Attributes: map[string]schema.Attribute{
			"port": schema.Int64Attribute{
				Required: true,
				Description: "Front-panel port number, 1-based as printed on the chassis. The device's own " +
					"API is zero-based; the client converts.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
				Description: "Whether the port participates in spanning tree. Defaults to true, which is " +
					"the shipped state and correct for every port that is not a known-bad edge device.",
			},
			"state": schema.StringAttribute{
				Computed: true,
				Description: "The port's current STP state as the device reports it - `Forwarding`, " +
					"`Blocking`, `Disabled`. Read-only.",
			},
		},
	}
}

func (r *ms510STPPortResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if c := ms510Client(req.ProviderData, &resp.Diagnostics, "per-port spanning tree"); c != nil {
		r.client = c
	}
}

func (r *ms510STPPortResource) get(port int) (*ms510txup.STPPort, error) {
	ports, err := r.client.ListSTPPorts()
	if err != nil {
		return nil, err
	}
	if port < 1 || port > len(ports) {
		return nil, nil
	}
	return &ports[port-1], nil
}

func (m *ms510STPPortModel) fromWire(p ms510txup.STPPort) {
	m.Enabled = types.BoolValue(p.Enable == 1)
	m.State = types.StringValue(ms510txup.PoELangValue(p.State))
}

func (r *ms510STPPortResource) apply(plan *ms510STPPortModel, diags diagSink) {
	port := int(plan.Port.ValueInt64())
	if err := r.client.SetSTPPortEnabled(port, plan.Enabled.ValueBool()); err != nil {
		diags.AddError("Could not set spanning tree for the port", err.Error())
		return
	}
	got, err := r.get(port)
	if err != nil {
		diags.AddError("Could not read back the port", err.Error())
		return
	}
	if got == nil {
		diags.AddError("No such port", fmt.Sprintf("Port %d does not exist on this switch.", port))
		return
	}
	plan.fromWire(*got)
}

func (r *ms510STPPortResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510STPPortModel
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

func (r *ms510STPPortResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510STPPortModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.get(int(state.Port.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Could not read the port", err.Error())
		return
	}
	if got == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510STPPortResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510STPPortModel
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

// Delete restores STP on the port, which is the shipped state. Unlike the PoE
// resource, the safe direction here is the default one: leaving a port outside
// spanning tree because a resource was removed from the config is how a loop
// goes unnoticed.
func (r *ms510STPPortResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ms510STPPortModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.SetSTPPortEnabled(int(state.Port.ValueInt64()), true); err != nil {
		resp.Diagnostics.AddError("Could not re-enable spanning tree on the port", err.Error())
	}
}

// ImportState takes the 1-based port number:
//
//	terraform import netgear_ms510txup_stp_port.ap 5
func (r *ms510STPPortResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	port, err := strconv.Atoi(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			"Import this resource with the port number, for example "+
				"`terraform import netgear_ms510txup_stp_port.ap 5`. Got: "+req.ID)
		return
	}
	got, err := r.get(port)
	if err != nil {
		resp.Diagnostics.AddError("Could not read the port", err.Error())
		return
	}
	if got == nil {
		resp.Diagnostics.AddError("No such port",
			fmt.Sprintf("Port %d does not exist on this switch.", port))
		return
	}
	state := ms510STPPortModel{Port: types.Int64Value(int64(port))}
	state.fromWire(*got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), port)...)
}
