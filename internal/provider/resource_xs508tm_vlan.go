package provider

import (
	"context"
	"fmt"
	"sort"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/xs508tm"
)

var (
	_ resource.Resource                = &xs508VLANResource{}
	_ resource.ResourceWithImportState = &xs508VLANResource{}
)

type xs508VLANResource struct {
	client *xs508tm.Client
}

func NewXS508VLANResource() resource.Resource { return &xs508VLANResource{} }

type xs508VLANModel struct {
	VLANID      types.Int64   `tfsdk:"vlan_id"`
	Name        types.String  `tfsdk:"name"`
	TaggedPorts []types.Int64 `tfsdk:"tagged_ports"`
}

func (r *xs508VLANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_vlan"
}

func (r *xs508VLANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A VLAN on the XS508TM and its TAGGED member ports, managed over the SSH CLI.\n\n" +
			"Never changes a port's PVID or untagged membership, so it is additive on a live trunk. " +
			"`tagged_ports` is authoritative for tagged membership of this VLAN: ports removed from the list " +
			"are excluded again. Changes are saved (`write memory`) and the save is verified.\n\n" +
			"Verified against firmware 7.8.11.21.\n\n" +
			"Destroying the resource deletes the VLAN.",
		Attributes: map[string]schema.Attribute{
			"vlan_id": schema.Int64Attribute{
				Required:      true,
				Description:   "VLAN ID, 2-4093.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{Required: true, Description: "VLAN name."},
			"tagged_ports": schema.ListAttribute{
				Required: true, ElementType: types.Int64Type,
				Description: "Front-panel port numbers carrying this VLAN tagged, ascending.",
			},
		},
	}
}

func (r *xs508VLANResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.XS508TM == nil {
		resp.Diagnostics.AddError("XS508TM not configured",
			"This resource manages the XS508TM. Add an `xs508tm` block to the provider, or set XS508TM_PASSWORD.")
		return
	}
	r.client = c.XS508TM
}

func ports(in []types.Int64) []int {
	out := make([]int, 0, len(in))
	for _, p := range in {
		out = append(out, int(p.ValueInt64()))
	}
	sort.Ints(out)
	return out
}

func (m *xs508VLANModel) set(v *xs508tm.VLAN) {
	m.Name = types.StringValue(v.Name)
	m.TaggedPorts = make([]types.Int64, 0, len(v.TaggedPorts))
	for _, p := range v.TaggedPorts {
		m.TaggedPorts = append(m.TaggedPorts, types.Int64Value(int64(p)))
	}
}

func (r *xs508VLANResource) write(plan *xs508VLANModel, previous []int) error {
	if err := r.client.SetVLAN(xs508tm.VLAN{
		ID: int(plan.VLANID.ValueInt64()), Name: plan.Name.ValueString(), TaggedPorts: ports(plan.TaggedPorts),
	}, previous); err != nil {
		return err
	}
	got, err := r.client.GetVLAN(int(plan.VLANID.ValueInt64()))
	if err != nil {
		return err
	}
	if got == nil {
		return fmt.Errorf("VLAN %d does not read back after the change", plan.VLANID.ValueInt64())
	}
	plan.set(got)
	return nil
}

func (r *xs508VLANResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan xs508VLANModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.write(&plan, nil); err != nil {
		resp.Diagnostics.AddError("Could not create VLAN", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *xs508VLANResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state xs508VLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetVLAN(int(state.VLANID.ValueInt64()))
	if err != nil {
		resp.Diagnostics.AddError("Could not read VLAN", err.Error())
		return
	}
	if got == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	state.set(got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *xs508VLANResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state xs508VLANModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.write(&plan, ports(state.TaggedPorts)); err != nil {
		resp.Diagnostics.AddError("Could not update VLAN", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *xs508VLANResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state xs508VLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteVLAN(int(state.VLANID.ValueInt64())); err != nil {
		resp.Diagnostics.AddError("Could not delete VLAN", err.Error())
	}
}

func (r *xs508VLANResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("Expected a numeric VLAN id, got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vlan_id"), id)...)
}
