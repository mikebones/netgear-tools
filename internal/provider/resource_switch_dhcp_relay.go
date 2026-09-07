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
	_ resource.Resource                = &switchDHCPRelayResource{}
	_ resource.ResourceWithImportState = &switchDHCPRelayResource{}
)

type switchDHCPRelayResource struct{ client *xs508tm.Client }

func NewSwitchDHCPRelayResource() resource.Resource { return &switchDHCPRelayResource{} }

type switchDHCPRelayModel struct {
	Enabled types.Bool     `tfsdk:"enabled"`
	Servers []types.String `tfsdk:"servers"`
}

func (r *switchDHCPRelayResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_dhcp_relay"
}

func (r *switchDHCPRelayResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "DHCP relay on the switch - the CLI's `ip helper enable` + `ip helper-address <ip> dhcp` " +
			"(dhcprelay_global_cfg + dhcprelay_server_cfg).\n\n" +
			"Relays DHCP from clients on the switch to a server that is not on their broadcast domain. Needs IP " +
			"routing on (netgear_xs508tm_ip_routing). The server list is REPLACED on every write - list every " +
			"helper address you want to keep.\n\n" +
			"Destroying the resource turns relaying off and clears the helper list.",
		Attributes: map[string]schema.Attribute{
			"enabled": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Default:  booldefault.StaticBool(true),
			},
			"servers": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "Helper (DHCP server) addresses to relay to.",
			},
		},
	}
}

func (r *switchDHCPRelayResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *switchDHCPRelayResource) apply(plan *switchDHCPRelayModel, diags interface {
	AddError(string, string)
}) {
	// Servers first, then the global flag, so a client that reads back an
	// enabled relay always finds its helper list already in place.
	servers := make([]xs508tm.DHCPRelayServer, 0, len(plan.Servers))
	for _, s := range plan.Servers {
		servers = append(servers, xs508tm.DHCPRelayServer{IP: s.ValueString()})
	}
	if err := r.client.SetDHCPRelayServers(servers); err != nil {
		diags.AddError("Could not set DHCP relay servers", err.Error())
		return
	}

	cur, err := r.client.GetDHCPRelayGlobal()
	if err != nil {
		diags.AddError("Could not read DHCP relay global config", err.Error())
		return
	}
	if plan.Enabled.ValueBool() {
		cur.State = 1
	} else {
		cur.State = 0
	}
	if err := r.client.SetDHCPRelayGlobal(cur); err != nil {
		diags.AddError("Could not set DHCP relay", err.Error())
		return
	}
	r.refresh(plan, diags)
}

// refresh reloads both halves into the model.
func (r *switchDHCPRelayResource) refresh(m *switchDHCPRelayModel, diags interface {
	AddError(string, string)
}) {
	g, err := r.client.GetDHCPRelayGlobal()
	if err != nil {
		diags.AddError("Could not read DHCP relay global config", err.Error())
		return
	}
	servers, err := r.client.GetDHCPRelayServers()
	if err != nil {
		diags.AddError("Could not read DHCP relay servers", err.Error())
		return
	}
	m.Enabled = types.BoolValue(g.State == 1)
	m.Servers = nil
	for _, s := range servers {
		m.Servers = append(m.Servers, types.StringValue(s.IP))
	}
}

func (r *switchDHCPRelayResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan switchDHCPRelayModel
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

func (r *switchDHCPRelayResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state switchDHCPRelayModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.refresh(&state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *switchDHCPRelayResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan switchDHCPRelayModel
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

// Delete turns relaying off and clears the helper list.
func (r *switchDHCPRelayResource) Delete(_ context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	if err := r.client.SetDHCPRelayServers(nil); err != nil {
		resp.Diagnostics.AddError("Could not clear DHCP relay servers", err.Error())
		return
	}
	cur, err := r.client.GetDHCPRelayGlobal()
	if err != nil {
		resp.Diagnostics.AddError("Could not read DHCP relay global config", err.Error())
		return
	}
	cur.State = 0
	if err := r.client.SetDHCPRelayGlobal(cur); err != nil {
		resp.Diagnostics.AddError("Could not disable DHCP relay", err.Error())
	}
}

func (r *switchDHCPRelayResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var m switchDHCPRelayModel
	r.refresh(&m, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
