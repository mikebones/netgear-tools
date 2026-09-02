package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/ms510txup"
)

var (
	_ resource.Resource                = &ms510DNSResource{}
	_ resource.ResourceWithImportState = &ms510DNSResource{}
)

type ms510DNSResource struct {
	client *ms510txup.Client
}

func NewMS510DNSResource() resource.Resource { return &ms510DNSResource{} }

type ms510DNSModel struct {
	Enabled    types.Bool     `tfsdk:"enabled"`
	DomainName types.String   `tfsdk:"domain_name"`
	Servers    []types.String `tfsdk:"servers"`
}

func (r *ms510DNSResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ms510txup_dns"
}

func (r *ms510DNSResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resolvers used by the MS510TXUP itself.\n\n" +
			"This is the switch's own DNS, not anything it hands to clients - it has no DHCP server role here. " +
			"It matters anyway: a switch pointed at a public resolver answers differently from every other host " +
			"on the LAN, so internal names do not resolve for it and its own queries bypass whatever filtering " +
			"and logging the LAN resolver provides.\n\n" +
			"The switch assigns each entry an index and a preference itself; neither can be requested. Ordering " +
			"is therefore not something this resource can control, and changing the list is delete-then-add.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default:     booldefault.StaticBool(true),
				Description: "Whether the resolver is active.",
			},
			"domain_name": schema.StringAttribute{
				Optional: true, Computed: true,
				Default:     stringdefault.StaticString(""),
				Description: "Default domain appended to unqualified names. Empty is fine and is how it ships.",
			},
			"servers": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "Resolver addresses, up to 8. Point these at the same resolver the rest of the LAN uses.",
			},
		},
	}
}

func (r *ms510DNSResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *ms510DNSResource) apply(plan *ms510DNSModel, diags interface {
	AddError(string, string)
}) {
	if err := r.client.SetDNSState(plan.Enabled.ValueBool(), plan.DomainName.ValueString()); err != nil {
		diags.AddError("Could not set the DNS state", err.Error())
		return
	}

	current, err := r.client.GetDNS()
	if err != nil {
		diags.AddError("Could not read the resolver list", err.Error())
		return
	}

	wanted := map[string]bool{}
	for _, s := range plan.Servers {
		wanted[s.ValueString()] = true
	}
	// Delete by the switch's own row index, not by position or address.
	have := map[string]bool{}
	for _, d := range current.DNS {
		if wanted[d.IP] {
			have[d.IP] = true
			continue
		}
		if err := r.client.DeleteDNSServer(d.Idx); err != nil {
			diags.AddError("Could not remove a resolver", err.Error())
			return
		}
	}
	for _, s := range plan.Servers {
		if have[s.ValueString()] {
			continue
		}
		if err := r.client.AddDNSServer(s.ValueString()); err != nil {
			diags.AddError("Could not add a resolver", err.Error())
			return
		}
	}

	r.readInto(plan, diags)
}

func (r *ms510DNSResource) readInto(m *ms510DNSModel, diags interface {
	AddError(string, string)
}) bool {
	got, err := r.client.GetDNS()
	if err != nil {
		diags.AddError("Could not read the DNS configuration", err.Error())
		return false
	}
	m.Enabled = types.BoolValue(got.State == 1)
	m.DomainName = types.StringValue(got.Hostname)
	m.Servers = nil
	for _, d := range got.DNS {
		m.Servers = append(m.Servers, types.StringValue(d.IP))
	}
	return true
}

func (r *ms510DNSResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ms510DNSModel
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

func (r *ms510DNSResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ms510DNSModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readInto(&state, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ms510DNSResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ms510DNSModel
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

// Delete disables the resolver but leaves the addresses in place. Removing the
// servers as well would leave a switch that cannot resolve anything, which is
// a worse default than one that is merely switched off.
func (r *ms510DNSResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ms510DNSModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.SetDNSState(false, state.DomainName.ValueString()); err != nil {
		resp.Diagnostics.AddError("Could not disable DNS", err.Error())
	}
}

func (r *ms510DNSResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var state ms510DNSModel
	if !r.readInto(&state, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
