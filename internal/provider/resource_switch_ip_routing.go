package provider

import (
	"context"

	"netgear-tools/internal/xs508tm"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &switchIPRoutingResource{}
	_ resource.ResourceWithImportState = &switchIPRoutingResource{}
)

type switchIPRoutingResource struct{ client *xs508tm.Client }

func NewSwitchIPRoutingResource() resource.Resource { return &switchIPRoutingResource{} }

type switchIPRoutingModel struct {
	Enabled types.Bool `tfsdk:"enabled"`
}

func (r *switchIPRoutingResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_ip_routing"
}

func (r *switchIPRoutingResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "IPv4 routing on the switch (ip_routing_cfg, the CLI's `ip routing`).\n\n" +
			"Enables L3 forwarding on the switch. On this network it is on alongside DHCP relay - the switch " +
			"relays DHCP for a subnet, which needs routing enabled. maxNextHops and defTTL are left as the " +
			"firmware reports them.\n\n" +
			"A settings singleton: destroying the resource turns routing off.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
		},
	}
}

func (r *switchIPRoutingResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.XS508TM == nil {
		resp.Diagnostics.AddError("XS508TM not configured",
			"This resource manages the switch. Add an `xs508tm` block to the provider, or set XS508TM_PASSWORD.")
		return
	}
	r.client = c.XS508TM
}

func (r *switchIPRoutingResource) apply(plan *switchIPRoutingModel, diags interface {
	AddError(string, string)
}) {
	if err := r.client.EnableIPRouting(plan.Enabled.ValueBool()); err != nil {
		diags.AddError("Could not set IP routing", err.Error())
		return
	}
	got, err := r.client.GetIPRouting()
	if err != nil {
		diags.AddError("Could not read back IP routing", err.Error())
		return
	}
	plan.Enabled = types.BoolValue(got.Admin == 1)
}

func (r *switchIPRoutingResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan switchIPRoutingModel
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

func (r *switchIPRoutingResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state switchIPRoutingModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetIPRouting()
	if err != nil {
		resp.Diagnostics.AddError("Could not read IP routing", err.Error())
		return
	}
	state.Enabled = types.BoolValue(got.Admin == 1)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *switchIPRoutingResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan switchIPRoutingModel
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

// Delete turns routing off.
func (r *switchIPRoutingResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.EnableIPRouting(false); err != nil {
		resp.Diagnostics.AddError("Could not disable IP routing", err.Error())
	}
}

func (r *switchIPRoutingResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetIPRouting()
	if err != nil {
		resp.Diagnostics.AddError("Could not read IP routing", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &switchIPRoutingModel{Enabled: types.BoolValue(got.Admin == 1)})...)
}
