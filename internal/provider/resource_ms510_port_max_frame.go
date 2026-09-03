package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510PortMaxFrameResource{}
	_ resource.ResourceWithImportState = &ms510PortMaxFrameResource{}
)

type ms510PortMaxFrameResource struct {
	client *ms510txup.Client
}

func NewMS510PortMaxFrameResource() resource.Resource { return &ms510PortMaxFrameResource{} }

type ms510PortMaxFrameModel struct {
	Port     types.Int64 `tfsdk:"port"`
	MaxFrame types.Int64 `tfsdk:"max_frame_size"`
}

func (r *ms510PortMaxFrameResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_port_max_frame"
}

func (r *ms510PortMaxFrameResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Maximum frame size for one front-panel port.\n\n" +
			"**This usually declares a dependency rather than changing anything.** The switch ships with " +
			"10000 already set, so a port carrying a jumbo VLAN needs no intervention - right up until " +
			"something resets it. This switch is known to clear configuration on a firmware upgrade (it has " +
			"dropped the syslog host and the SNTP server that way), and a frame size quietly back at 1500 " +
			"breaks a storage network with no other symptom: small packets still flow, so the port looks fine " +
			"and only bulk transfer collapses.\n\n" +
			"Declaring it means `terraform plan` reports that regression instead of someone finding it later.\n\n" +
			"Accepts 1522-10000. Note the floor is 1522, not 1500 - the switch counts the VLAN tag and FCS, " +
			"so an MTU of 1500 is already a 1522-byte frame here.",
		Attributes: map[string]schema.Attribute{
			"port": schema.Int64Attribute{
				Required:    true,
				Description: "Front-panel port number.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
			},
			"max_frame_size": schema.Int64Attribute{
				Required: true,
				Description: "Maximum frame size in bytes, 1522-10000. This is the frame, not the MTU: " +
					"allow at least MTU + 18 for the Ethernet header, VLAN tag and FCS.",
			},
		},
	}
}

func (r *ms510PortMaxFrameResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.MS510TXUP == nil {
		resp.Diagnostics.AddError("MS510TXUP not configured",
			"This resource manages the PoE switch. Add an `ms510txup` block to the provider, or set MS510TXUP_PASSWORD.")
		return
	}
	r.client = c.MS510TXUP
}

func (r *ms510PortMaxFrameResource) apply(plan *ms510PortMaxFrameModel, diags interface {
	AddError(string, string)
}) {
	port := int(plan.Port.ValueInt64())
	if err := r.client.SetPortMaxFrame(port, int(plan.MaxFrame.ValueInt64())); err != nil {
		diags.AddError(fmt.Sprintf("Could not set the max frame size on port %d", port), err.Error())
		return
	}
	got, err := r.client.GetPortMaxFrame(port)
	if err != nil {
		diags.AddError(fmt.Sprintf("Could not read back port %d", port), err.Error())
		return
	}
	plan.MaxFrame = types.Int64Value(int64(got))
}

func (r *ms510PortMaxFrameResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510PortMaxFrameModel
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

func (r *ms510PortMaxFrameResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510PortMaxFrameModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetPortMaxFrame(int(state.Port.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Could not read the port max frame size", err.Error())
		return
	}
	state.MaxFrame = types.Int64Value(int64(got))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510PortMaxFrameResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510PortMaxFrameModel
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

// Delete leaves the port where it is. This resource almost always describes
// the shipped value, so "destroying" it should not go out and shrink a frame
// size that something is actively relying on - removing a description of the
// world should not change the world.
func (r *ms510PortMaxFrameResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

func (r *ms510PortMaxFrameResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	port, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			fmt.Sprintf("Import by port number, for example `terraform import ... 10`. Got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("port"), port)...)
}
