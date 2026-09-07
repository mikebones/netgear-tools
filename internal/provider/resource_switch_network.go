package provider

import (
	"context"

	"netgear-tools/internal/xs508tm"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &switchNetworkResource{}
	_ resource.ResourceWithImportState = &switchNetworkResource{}
)

type switchNetworkResource struct{ client *xs508tm.Client }

func NewSwitchNetworkResource() resource.Resource { return &switchNetworkResource{} }

type switchNetworkModel struct {
	MgmtVID types.Int64  `tfsdk:"mgmt_vid"`
	Mode    types.Int64  `tfsdk:"mode"`
	IP      types.String `tfsdk:"ip"`
	Subnet  types.String `tfsdk:"subnet"`
	Gateway types.String `tfsdk:"gateway"`
}

func (r *switchNetworkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_xs508tm_network"
}

func (r *switchNetworkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The switch's management-interface addressing (ip_network_cfg).\n\n" +
			"WHY THIS EXISTS: the management IP was the one setting that lived nowhere but the device. A factory " +
			"reset dropped it and recovering the switch meant hunting its DHCP lease and rebuilding .3 by hand. " +
			"Captured here, the desired address is documented and drift against it is visible on every plan.\n\n" +
			"DANGER - this resource writes the address the management plane answers on. Because the provider " +
			"reaches the switch THROUGH that address, changing `ip` moves the switch out from under the very " +
			"connection making the change: the write goes out but the read-back cannot follow it to the new " +
			"address. This resource therefore trusts a successful write and does NOT fail on the post-move " +
			"read-back, but Terraform's endpoint is now stale - update the provider's xs508tm endpoint and run " +
			"again to confirm. If the new address is unreachable from the host running Terraform there is no way " +
			"back over IPv4; recover over IPv6 link-local (see docs/xs508tm-recovery.md). In normal steady-state " +
			"use `ip` matches the endpoint, the write is a no-op and the read-back confirms drift.\n\n" +
			"`mode` is the firmware protocol enum (3 = DHCP). For a static address use the value the device " +
			"reports for `network protocol none` - import an already-configured switch rather than guessing it.",
		Attributes: map[string]schema.Attribute{
			"mgmt_vid": schema.Int64Attribute{
				Optional: true, Computed: true,
				Default:     int64default.StaticInt64(1),
				Description: "Management VLAN id.",
			},
			"mode": schema.Int64Attribute{
				Required:    true,
				Description: "Protocol enum: 3 = DHCP; the static/none value is what the device reports for `network protocol none`.",
			},
			"ip":      schema.StringAttribute{Required: true},
			"subnet":  schema.StringAttribute{Required: true},
			"gateway": schema.StringAttribute{Required: true},
		},
	}
}

func (r *switchNetworkResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m switchNetworkModel) toConfig() xs508tm.IPNetworkConfig {
	return xs508tm.IPNetworkConfig{
		MgmtVID: int(m.MgmtVID.ValueInt64()),
		Mode:    int(m.Mode.ValueInt64()),
		IP:      m.IP.ValueString(),
		Subnet:  m.Subnet.ValueString(),
		Gateway: m.Gateway.ValueString(),
	}
}

func applyNetwork(m *switchNetworkModel, c xs508tm.IPNetworkConfig) {
	m.MgmtVID = types.Int64Value(int64(c.MgmtVID))
	m.Mode = types.Int64Value(int64(c.Mode))
	m.IP = types.StringValue(c.IP)
	m.Subnet = types.StringValue(c.Subnet)
	m.Gateway = types.StringValue(c.Gateway)
}

func (r *switchNetworkResource) apply(plan *switchNetworkModel, diags interface {
	AddError(string, string)
	AddWarning(string, string)
}) {
	if err := r.client.SetIPNetworkConfig(plan.toConfig()); err != nil {
		diags.AddError("Could not set management network config", err.Error())
		return
	}
	// The write may have just moved the switch to a new IP, in which case the
	// read-back cannot reach it through the (now stale) endpoint. Trust the
	// write; confirm only if the switch still answers where we are pointed.
	got, err := r.client.GetIPNetworkConfig()
	if err != nil {
		diags.AddWarning("Management IP changed - endpoint is now stale",
			"The switch accepted the new addressing and is no longer reachable at the provider's configured "+
				"endpoint. Update the xs508tm endpoint to the new address and run again to confirm. Error on "+
				"read-back: "+err.Error())
		return // leave plan values in state; they are what we asked for
	}
	applyNetwork(plan, got)
}

func (r *switchNetworkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan switchNetworkModel
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

func (r *switchNetworkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state switchNetworkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	got, err := r.client.GetIPNetworkConfig()
	if err != nil {
		resp.Diagnostics.AddError("Could not read management network config", err.Error())
		return
	}
	applyNetwork(&state, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *switchNetworkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan switchNetworkModel
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

// Delete is deliberately a NO-OP on the device. The management IP is not a
// setting to "turn off" - resetting it here would strand the switch, the exact
// failure this resource exists to prevent. Removing the resource only drops it
// from state; the switch keeps its address.
func (r *switchNetworkResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

func (r *switchNetworkResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	got, err := r.client.GetIPNetworkConfig()
	if err != nil {
		resp.Diagnostics.AddError("Could not read management network config", err.Error())
		return
	}
	var m switchNetworkModel
	applyNetwork(&m, got)
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
