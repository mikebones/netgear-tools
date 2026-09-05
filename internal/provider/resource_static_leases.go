package provider

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/pr60x"
)

var (
	_ resource.Resource                = &staticLeasesResource{}
	_ resource.ResourceWithImportState = &staticLeasesResource{}
)

type staticLeasesResource struct {
	client *pr60x.Client
}

func NewStaticLeasesResource() resource.Resource { return &staticLeasesResource{} }

type staticLeaseEntry struct {
	Name types.String `tfsdk:"name"`
	IP   types.String `tfsdk:"ip"`
	MAC  types.String `tfsdk:"mac"`
}

type staticLeasesModel struct {
	VLANID types.Int64 `tfsdk:"vlan_id"`
	Leases types.Set   `tfsdk:"leases"`
}

// staticLeaseObjectType is the element type of the leases set. Declared once
// because Read, Create and ImportState all have to agree on it exactly.
func staticLeaseObjectType() attr.Type {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name": types.StringType,
		"ip":   types.StringType,
		"mac":  types.StringType,
	}}
}

func (r *staticLeasesResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_static_leases"
}

func (r *staticLeasesResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Every DHCP reservation on one VLAN, as a set.\n\n" +
			"PLURAL, AND THAT IS NOT A STYLE CHOICE. The device's addStaticLeaseProfiles takes the COMPLETE " +
			"list and replaces it - the name says add, the behaviour is set. A resource per reservation would " +
			"mean each one doing a read-modify-write against the same list, so two applying concurrently would " +
			"silently delete each other. Managing the whole list in one resource makes that impossible to " +
			"express.\n\n" +
			"THE ADDRESS MUST ALREADY HOLD A LEASE. The router rejects a reservation for an address it has " +
			"never leased, and rejects it SILENTLY: no error, the list simply comes back unchanged. Verified " +
			"against firmware 3.0.0.105 with both an out-of-pool address and a free in-pool one. So a host has " +
			"to boot and take a lease before it can be pinned - you cannot pre-declare one. When that happens " +
			"the apply reports success and the next plan shows the entry missing again; this resource raises a " +
			"warning naming the dropped addresses rather than leaving you to work that out.\n\n" +
			"A reservation pins an address without changing it, which is why this is the right tool for a host " +
			"already in service: no renumbering, so no kubelet re-registration and nothing that resolves the " +
			"host by name has to change.",
		Attributes: map[string]schema.Attribute{
			"vlan_id": schema.Int64Attribute{
				Required: true,
				Description: "VLAN whose reservation list this manages. Required on read as well as write - " +
					"getStaticLeaseProfiles called without it returns null, which looks exactly like " +
					"'there are no reservations'.",
			},
			"leases": schema.SetNestedAttribute{
				Required: true,
				Description: "The complete set of reservations for this VLAN. A set rather than a list because " +
					"the device's id is a positional index it renumbers on every write - ordering carries no " +
					"meaning, and treating it as significant would produce permanent spurious diffs.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required:    true,
							Description: "Label shown in the router UI. The device stores '---' for an empty name.",
						},
						"ip": schema.StringAttribute{
							Required:    true,
							Description: "Address to pin. Must already hold a DHCP lease - see the resource description.",
						},
						"mac": schema.StringAttribute{
							Required: true,
							Description: "MAC to pin it to. The device returns these upper-case; write them " +
								"upper-case or every plan shows a diff.",
						},
					},
				},
			},
		},
	}
}

func (r *staticLeasesResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func leasesToAPI(ctx context.Context, set types.Set, diags diagSink) []pr60x.StaticLease {
	var entries []staticLeaseEntry
	if d := set.ElementsAs(ctx, &entries, false); d.HasError() {
		diags.AddError("Could not read the leases set", fmt.Sprintf("%v", d.Errors()))
		return nil
	}
	out := make([]pr60x.StaticLease, 0, len(entries))
	for _, e := range entries {
		out = append(out, pr60x.StaticLease{
			Name: e.Name.ValueString(),
			IP:   e.IP.ValueString(),
			MAC:  e.MAC.ValueString(),
		})
	}
	return out
}

func leasesToSet(ctx context.Context, in []pr60x.StaticLease) (types.Set, error) {
	entries := make([]staticLeaseEntry, 0, len(in))
	for _, l := range in {
		entries = append(entries, staticLeaseEntry{
			Name: types.StringValue(l.Name),
			IP:   types.StringValue(l.IP),
			MAC:  types.StringValue(l.MAC),
		})
	}
	set, d := types.SetValueFrom(ctx, staticLeaseObjectType(), entries)
	if d.HasError() {
		return types.SetNull(staticLeaseObjectType()), fmt.Errorf("%v", d.Errors())
	}
	return set, nil
}

// diagSink is the subset of diag.Diagnostics used here, so the same helper
// serves Create, Read and Update without importing the concrete type.
type diagSink interface {
	AddError(string, string)
	AddWarning(string, string)
}

// write sets the list and reads it straight back, because the device drops
// entries it will not accept WITHOUT reporting an error. Reading back is the
// only way a caller ever finds out, so it is not optional here.
func (r *staticLeasesResource) write(ctx context.Context, plan *staticLeasesModel, diags diagSink) {
	want := leasesToAPI(ctx, plan.Leases, diags)
	if want == nil {
		return
	}
	if err := r.client.SetStaticLeases(plan.VLANID.ValueInt64(), want); err != nil {
		diags.AddError("Could not set static leases", err.Error())
		return
	}
	got, err := r.client.ListStaticLeases(plan.VLANID.ValueInt64())
	if err != nil {
		diags.AddError("Could not read back static leases", err.Error())
		return
	}
	if len(got) != len(want) {
		have := map[string]bool{}
		for _, g := range got {
			have[g.IP] = true
		}
		missing := []string{}
		for _, w := range want {
			if !have[w.IP] {
				missing = append(missing, w.IP)
			}
		}
		diags.AddWarning("The router did not accept every reservation",
			"Asked for "+strconv.Itoa(len(want))+" reservations, the device kept "+strconv.Itoa(len(got))+
				". Dropped: "+fmt.Sprint(missing)+"\n\n"+
				"The usual cause is an address that does not currently hold a DHCP lease - the router "+
				"rejects those silently. Let the host boot and take a lease, then apply again.")
	}
	set, err := leasesToSet(ctx, got)
	if err != nil {
		diags.AddError("Could not build the leases set", err.Error())
		return
	}
	plan.Leases = set
}

func (r *staticLeasesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan staticLeasesModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *staticLeasesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state staticLeasesModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.ListStaticLeases(state.VLANID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Could not read static leases", err.Error())
		return
	}
	set, err := leasesToSet(ctx, got)
	if err != nil {
		resp.Diagnostics.AddError("Could not build the leases set", err.Error())
		return
	}
	state.Leases = set
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *staticLeasesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan staticLeasesModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.write(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete clears the VLAN's reservations. Every address then falls back to a
// dynamic lease, which is what the network looked like before this resource
// existed - the honest inverse of creating it.
func (r *staticLeasesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state staticLeasesModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.SetStaticLeases(state.VLANID.ValueInt64(), nil); err != nil {
		resp.Diagnostics.AddError("Could not clear static leases", err.Error())
	}
}

// ImportState takes the VLAN id, since that is the only thing identifying
// which list this resource owns:
//
//	terraform import netgear_pr60x_static_leases.lan 1
func (r *staticLeasesResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vlan, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID",
			"Import this resource with the VLAN id, for example "+
				"`terraform import netgear_pr60x_static_leases.lan 1`. Got: "+req.ID)
		return
	}
	got, err := r.client.ListStaticLeases(vlan)
	if err != nil {
		resp.Diagnostics.AddError("Could not read static leases", err.Error())
		return
	}
	set, err := leasesToSet(ctx, got)
	if err != nil {
		resp.Diagnostics.AddError("Could not build the leases set", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &staticLeasesModel{
		VLANID: types.Int64Value(vlan),
		Leases: set,
	})...)
}
