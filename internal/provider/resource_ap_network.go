package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"netgear-tools/internal/wax630e"
)

var (
	_ resource.Resource                = &apNetworkResource{}
	_ resource.ResourceWithImportState = &apNetworkResource{}
)

type apNetworkResource struct {
	client *wax630e.Client
}

func NewAPNetworkResource() resource.Resource { return &apNetworkResource{} }

type apNetworkModel struct {
	DHCP         types.Bool   `tfsdk:"dhcp"`
	IPAddress    types.String `tfsdk:"ip_address"`
	SubnetMask   types.String `tfsdk:"subnet_mask"`
	Gateway      types.String `tfsdk:"gateway"`
	PrimaryDNS   types.String `tfsdk:"primary_dns"`
	SecondaryDNS types.String `tfsdk:"secondary_dns"`
	ManagementVL types.Int64  `tfsdk:"management_vlan_id"`
}

func (r *apNetworkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_wax630e_network"
}

func (r *apNetworkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Management addressing for the access point.\n\n" +
			"**The static fields are stored independently of the DHCP flag, and they ship as factory " +
			"defaults** - 192.168.0.100 with a 192.168.0.1 gateway. Turning DHCP off without supplying an " +
			"address in the same write therefore does not leave the AP where it is: it drops onto a different " +
			"subnet and off the network. This resource always writes the whole block for that reason.\n\n" +
			"Changing the address moves the AP immediately, so the provider's `wax630e` endpoint has to be " +
			"updated to match in the same change - Terraform cannot follow a device that has moved out from " +
			"under it.",
		Attributes: map[string]schema.Attribute{
			"dhcp": schema.BoolAttribute{
				Optional: true, Computed: true,
				Default: booldefault.StaticBool(false),
				Description: "Take the address from DHCP. False means static, which is what you want for " +
					"anything Terraform points at by literal address.",
			},
			"ip_address": schema.StringAttribute{
				Required:    true,
				Description: "Management address. Keep it outside the router's DHCP pool.",
			},
			"subnet_mask": schema.StringAttribute{
				Optional: true, Computed: true,
				Default: stringdefault.StaticString("255.255.255.0"),
			},
			"gateway": schema.StringAttribute{
				Required: true,
			},
			"primary_dns": schema.StringAttribute{
				Optional: true, Computed: true,
				Default: stringdefault.StaticString(""),
				Description: "Resolver. Point it at the same one the rest of the LAN uses - an AP on a public " +
					"resolver cannot see internal names and skips whatever filtering and logging everything " +
					"else is subject to.",
			},
			"secondary_dns": schema.StringAttribute{
				Optional: true, Computed: true,
				Default: stringdefault.StaticString(""),
				Description: "Second resolver. Note the AP DISCARDS an empty string here rather than " +
					"clearing the field, so a blank cannot be used to remove the factory 8.8.4.4 - the " +
					"only way to displace a public resolver is to write a real address over it.",
			},
			"management_vlan_id": schema.Int64Attribute{
				Optional: true, Computed: true,
				Description: "VLAN the management interface lives on. Read back from the device; changing it " +
					"moves management to another VLAN, so it is not defaulted here.",
			},
		},
	}
}

func (r *apNetworkResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.WAX630E == nil {
		resp.Diagnostics.AddError("WAX630E not configured",
			"This resource manages the access point. Add a `wax630e` block to the provider, or set WAX630E_PASSWORD.")
		return
	}
	r.client = c.WAX630E
}

func applyAPNetwork(dst *apNetworkModel, n wax630e.NetworkSettings) {
	dst.DHCP = types.BoolValue(n.DHCPClientStatus == "1")
	dst.IPAddress = types.StringValue(n.IPAddr)
	dst.SubnetMask = types.StringValue(n.NetmaskAddr)
	dst.Gateway = types.StringValue(n.GatewayAddr)
	dst.PrimaryDNS = types.StringValue(n.PrimaryDNS)
	dst.SecondaryDNS = types.StringValue(n.SecondaryDNS)
	if v := parseInt64(n.ManagementVLANID); v > 0 {
		dst.ManagementVL = types.Int64Value(v)
	}
}

func parseInt64(s string) int64 {
	var n int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int64(c-'0')
	}
	if s == "" {
		return 0
	}
	return n
}

func (r *apNetworkResource) apply(plan *apNetworkModel, diags interface {
	AddError(string, string)
}) {
	// Read first so the fields this resource does not model - device mode,
	// untagged VLAN, inter-VLAN routing - are carried through rather than
	// blanked. A partial write here is how an AP ends up on 192.168.0.100.
	cur, err := r.client.GetNetwork()
	if err != nil {
		diags.AddError("Could not read the AP network settings", err.Error())
		return
	}

	next := cur
	next.DHCPClientStatus = "0"
	if plan.DHCP.ValueBool() {
		next.DHCPClientStatus = "1"
	}
	next.IPAddr = plan.IPAddress.ValueString()
	next.NetmaskAddr = plan.SubnetMask.ValueString()
	next.GatewayAddr = plan.Gateway.ValueString()
	next.PrimaryDNS = plan.PrimaryDNS.ValueString()
	next.SecondaryDNS = plan.SecondaryDNS.ValueString()
	if !plan.ManagementVL.IsNull() && !plan.ManagementVL.IsUnknown() {
		next.ManagementVLANID = itoa(plan.ManagementVL.ValueInt64())
	}

	// Writing this block restarts the AP's networking - EVERY time, not just
	// when the address changes. The request it arrived on is one of the
	// casualties, so the write reliably ends in a read timeout even when it
	// succeeded. An error here is therefore not evidence of failure and cannot
	// be treated as one; the read-back below is what decides.
	movingTo := next.IPAddr != cur.IPAddr
	_ = r.client.SetNetwork(next)

	// A changed address means the AP is no longer where the provider is
	// pointed, so there is nothing to read back from - the endpoint has to be
	// updated in the same change before Terraform can reach it again.
	if movingTo {
		applyAPNetwork(plan, next)
		return
	}
	if !r.readBack(plan, diags) {
		return
	}
}

// readBack waits out the networking restart. The AP answers pings well before
// it answers on the management port, so this retries rather than sleeping once
// on a guessed interval.
func (r *apNetworkResource) readBack(m *apNetworkModel, diags interface {
	AddError(string, string)
}) bool {
	var last error
	for attempt := 0; attempt < 6; attempt++ {
		time.Sleep(20 * time.Second)
		got, err := r.client.GetNetwork()
		if err == nil {
			applyAPNetwork(m, got)
			return true
		}
		last = err
	}
	diags.AddError("The AP did not come back after the network write",
		"The settings were written and the AP restarted its networking, but it "+
			"never answered again within two minutes. Check whether it landed on "+
			"the address it was given.\n\nLast error: "+last.Error())
	return false
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

func (r *apNetworkResource) readInto(m *apNetworkModel, diags interface {
	AddError(string, string)
}) bool {
	got, err := r.client.GetNetwork()
	if err != nil {
		diags.AddError("Could not read the AP network settings", err.Error())
		return false
	}
	applyAPNetwork(m, got)
	return true
}

func (r *apNetworkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan apNetworkModel
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

func (r *apNetworkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state apNetworkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readInto(&state, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *apNetworkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan apNetworkModel
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

// Delete does NOT revert the AP to DHCP. Reverting would move the device to
// whatever a lease happens to give it, which is the failure this resource
// exists to prevent - and it would do so at the moment someone is tidying up
// configuration, which is the worst time to lose a device.
func (r *apNetworkResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (r *apNetworkResource) ImportState(ctx context.Context, _ resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	var state apNetworkModel
	if !r.readInto(&state, &resp.Diagnostics) {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
