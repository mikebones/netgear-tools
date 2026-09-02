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

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510VLANResource{}
	_ resource.ResourceWithImportState = &ms510VLANResource{}
)

type ms510VLANResource struct {
	client *ms510txup.Client
}

func NewMS510VLANResource() resource.Resource { return &ms510VLANResource{} }

type ms510VLANModel struct {
	VLANID        types.Int64   `tfsdk:"vlan_id"`
	Name          types.String  `tfsdk:"name"`
	TaggedPorts   []types.Int64 `tfsdk:"tagged_ports"`
	UntaggedPorts []types.Int64 `tfsdk:"untagged_ports"`
}

func (r *ms510VLANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_vlan"
}

func (r *ms510VLANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A VLAN on the MS510TXUP and which ports belong to it.\n\n" +
			"Ports are numbered as they are on the front of the switch, 1-10. The firmware indexes them from " +
			"zero internally and follows them with eight LAG slots; that translation is handled here so the " +
			"configuration reads like the hardware.\n\n" +
			"**This resource never changes a port's PVID.** Adding a port as `tagged` therefore leaves its " +
			"untagged traffic exactly where it was, which is what makes it safe to apply to a switch carrying " +
			"live traffic. A tagged VLAN is additive: hosts that know nothing about it are unaffected.\n\n" +
			"Destroying the resource deletes the VLAN, which removes every port from it at once.",
		Attributes: map[string]schema.Attribute{
			"vlan_id": schema.Int64Attribute{
				Required:      true,
				Description:   "VLAN ID, 2-4093. VLAN 1 is the default and is not managed here.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "VLAN name, up to 32 characters.",
			},
			"tagged_ports": schema.ListAttribute{
				Optional:    true,
				ElementType: types.Int64Type,
				Description: "Front-panel ports (1-10) that carry this VLAN tagged.",
			},
			"untagged_ports": schema.ListAttribute{
				Optional:    true,
				ElementType: types.Int64Type,
				Description: "Front-panel ports (1-10) that carry this VLAN untagged. Note that untagged " +
					"membership alone does not set the port's PVID, so incoming untagged frames still land " +
					"on the port's existing PVID - set that separately if you need it.",
			},
		},
	}
}

func (r *ms510VLANResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// statesFrom builds the full per-port state slice the firmware expects.
// Front-panel port N is index N-1.
func statesFrom(m *ms510VLANModel) ([]int, error) {
	states := make([]int, 18)
	set := func(ports []types.Int64, state int, what string) error {
		for _, p := range ports {
			n := p.ValueInt64()
			if n < 1 || n > 10 {
				return fmt.Errorf("%s port %d is outside the front panel range 1-10", what, n)
			}
			states[n-1] = state
		}
		return nil
	}
	if err := set(m.UntaggedPorts, ms510txup.VLANUntagged, "untagged"); err != nil {
		return nil, err
	}
	if err := set(m.TaggedPorts, ms510txup.VLANTagged, "tagged"); err != nil {
		return nil, err
	}
	return states, nil
}

func (r *ms510VLANResource) readInto(m *ms510VLANModel, diags interface {
	AddError(string, string)
}) bool {
	id := int(m.VLANID.ValueInt64())

	vlans, err := r.client.ListVLANs()
	if err != nil {
		diags.AddError("Could not list VLANs", err.Error())
		return false
	}
	found := false
	for _, v := range vlans {
		if v.ID == id {
			m.Name = types.StringValue(v.Name)
			found = true
			break
		}
	}
	if !found {
		return false
	}

	states, err := r.client.GetVLANMembership(id)
	if err != nil {
		diags.AddError("Could not read VLAN membership", err.Error())
		return false
	}
	m.TaggedPorts, m.UntaggedPorts = nil, nil
	for i, st := range states {
		if i >= 10 { // only the front panel; the rest are LAG slots
			break
		}
		switch st {
		case ms510txup.VLANTagged:
			m.TaggedPorts = append(m.TaggedPorts, types.Int64Value(int64(i+1)))
		case ms510txup.VLANUntagged:
			m.UntaggedPorts = append(m.UntaggedPorts, types.Int64Value(int64(i+1)))
		}
	}
	sortInt64(m.TaggedPorts)
	sortInt64(m.UntaggedPorts)
	return true
}

func sortInt64(v []types.Int64) {
	sort.Slice(v, func(i, j int) bool { return v[i].ValueInt64() < v[j].ValueInt64() })
}

func (r *ms510VLANResource) apply(plan *ms510VLANModel, create bool, diags interface {
	AddError(string, string)
}) {
	id := int(plan.VLANID.ValueInt64())

	if create {
		vlans, err := r.client.ListVLANs()
		if err != nil {
			diags.AddError("Could not list VLANs", err.Error())
			return
		}
		exists := false
		for _, v := range vlans {
			if v.ID == id {
				exists = true
				break
			}
		}
		if exists {
			diags.AddError("VLAN already exists",
				fmt.Sprintf("VLAN %d is already on the switch. Import it with: "+
					"terraform import netgear_ms510txup_vlan.<name> %d", id, id))
			return
		}
		if err := r.client.CreateVLAN(id, plan.Name.ValueString()); err != nil {
			diags.AddError("Could not create the VLAN", err.Error())
			return
		}
	}

	states, err := statesFrom(plan)
	if err != nil {
		diags.AddError("Invalid port list", err.Error())
		return
	}
	if err := r.client.SetVLANMembership(id, states); err != nil {
		diags.AddError("Could not set VLAN membership", err.Error())
		return
	}

	// This firmware reports save_success for writes it discarded, so the
	// read-back is the only real confirmation.
	if !r.readInto(plan, diags) {
		diags.AddError("VLAN missing after write",
			fmt.Sprintf("VLAN %d was not present on read-back.", id))
	}
}

func (r *ms510VLANResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510VLANModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(&plan, true, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ms510VLANResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510VLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readInto(&state, &resp.Diagnostics) {
		if !resp.Diagnostics.HasError() {
			resp.State.RemoveResource(ctx)
		}
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510VLANResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510VLANModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(&plan, false, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ms510VLANResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ms510VLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteVLAN(int(state.VLANID.ValueInt64())); err != nil {
		resp.Diagnostics.AddError("Could not delete the VLAN", err.Error())
	}
}

func (r *ms510VLANResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// The import id arrives as a string; vlan_id is an Int64, and handing the
	// raw string straight to SetAttribute fails with a value conversion error
	// rather than anything that names the problem.
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import id",
			fmt.Sprintf("Expected a numeric VLAN id, got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vlan_id"), id)...)
}
