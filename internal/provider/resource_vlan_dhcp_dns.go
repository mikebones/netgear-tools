package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &vlanDHCPDNSResource{}
	_ resource.ResourceWithImportState = &vlanDHCPDNSResource{}
)

type vlanDHCPDNSResource struct {
	client *client
}

func NewVLANDHCPDNSResource() resource.Resource {
	return &vlanDHCPDNSResource{}
}

type vlanDHCPDNSModel struct {
	VLANID  types.Int64 `tfsdk:"vlan_id"`
	Servers types.List  `tfsdk:"servers"`
}

func (r *vlanDHCPDNSResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vlan_dhcp_dns"
}

func (r *vlanDHCPDNSResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The DNS servers a VLAN's DHCP server advertises (DHCP option 6).\n\n" +
			"This is the setting behind most \"why does this name resolve only half the time?\" problems: hand " +
			"clients both a local resolver and a public one and they get two nameservers with no rule for " +
			"choosing, so lookups for private zones fail intermittently. List only the resolvers that actually " +
			"know your private zones.\n\n" +
			"Scoped deliberately narrowly. It adopts an existing VLAN and manages one field; it does not create " +
			"or destroy VLANs, and it does not touch addressing, the DHCP range or port membership. Changing " +
			"option 6 cannot partition the network - it only affects what future leases advertise, and existing " +
			"clients keep their current resolvers until they renew.",
		Attributes: map[string]schema.Attribute{
			"vlan_id": schema.Int64Attribute{
				Required:      true,
				Description:   "VLAN to manage, e.g. 1 for the default VLAN.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"servers": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "Ordered list of DNS server addresses to advertise. Order is preserved as given.",
			},
		},
	}
}

func (r *vlanDHCPDNSResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*client)
}

func (r *vlanDHCPDNSResource) apply(ctx context.Context, plan *vlanDHCPDNSModel, diags *diag.Diagnostics) {
	var servers []string
	diags.Append(plan.Servers.ElementsAs(ctx, &servers, false)...)
	if diags.HasError() {
		return
	}
	if err := r.client.setVLANDHCPDNS(plan.VLANID.ValueInt64(), servers); err != nil {
		diags.AddError("Could not set DHCP DNS servers", err.Error())
		return
	}

	// Read back, so state records what the device stored rather than what we
	// asked for.
	got, err := r.client.vlanDHCPDNS(plan.VLANID.ValueInt64())
	if err != nil {
		diags.AddError("Could not read back DHCP DNS servers", err.Error())
		return
	}
	list, d := types.ListValueFrom(ctx, types.StringType, got)
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	plan.Servers = list
}

func (r *vlanDHCPDNSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan vlanDHCPDNSModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *vlanDHCPDNSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state vlanDHCPDNSModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	got, err := r.client.vlanDHCPDNS(state.VLANID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Could not read DHCP DNS servers", err.Error())
		return
	}
	list, d := types.ListValueFrom(ctx, types.StringType, got)
	resp.Diagnostics.Append(d...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Servers = list
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *vlanDHCPDNSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan vlanDHCPDNSModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.apply(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete intentionally does nothing to the device. "No DHCP DNS servers" is
// not a meaningful state to leave a VLAN in, and guessing at a previous value
// would be worse than leaving the current one in place. Removing this resource
// stops Terraform managing the field; it does not revert it.
func (r *vlanDHCPDNSResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

func (r *vlanDHCPDNSResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid import id",
			fmt.Sprintf("Expected a numeric VLAN id, got %q.", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vlan_id"), id)...)
}
