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

	"netgear-tools/internal/pr60x"
)

var (
	_ resource.Resource                = &pr60xVLANResource{}
	_ resource.ResourceWithImportState = &pr60xVLANResource{}
)

type pr60xVLANResource struct {
	client *pr60x.Client
}

func NewPR60XVLANResource() resource.Resource { return &pr60xVLANResource{} }

type pr60xVLANModel struct {
	VLANID           types.Int64    `tfsdk:"vlan_id"`
	Name             types.String   `tfsdk:"name"`
	InterVLANRouting types.Bool     `tfsdk:"inter_vlan_routing"`
	DeviceManagement types.Bool     `tfsdk:"device_management"`
	IPAddress        types.String   `tfsdk:"ip_address"`
	Netmask          types.String   `tfsdk:"netmask"`
	DHCPEnabled      types.Bool     `tfsdk:"dhcp_enabled"`
	DHCPStart        types.String   `tfsdk:"dhcp_start"`
	DHCPEnd          types.String   `tfsdk:"dhcp_end"`
	DHCPLeaseSeconds types.Int64    `tfsdk:"dhcp_lease_seconds"`
	DNSServers       []types.String `tfsdk:"dns_servers"`
	DomainName       types.String   `tfsdk:"domain_name"`
	TaggedPorts      []types.Int64  `tfsdk:"tagged_ports"`
	UntaggedPorts    []types.Int64  `tfsdk:"untagged_ports"`
}

func (r *pr60xVLANResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_vlan"
}

func (r *pr60xVLANResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A VLAN profile on the PR60X router: its gateway address, DHCP server and LAN-port membership.\n\n" +
			"Ports are the router's LAN ports 1-5 (lan1..lan5).\n\n" +
			"`inter_vlan_routing` is the router's per-VLAN \"Inter VLAN Routing\" switch: VLANs are isolated from " +
			"each other unless it is on for both, and traffic rules (`netgear_pr60x_traffic_rules`) then filter " +
			"between them.\n\n" +
			"VLAN 1 (the LAN) can be imported and managed, but destroying it is refused - removing it from " +
			"configuration only stops Terraform managing it. Other VLANs are deleted on destroy.\n\n" +
			"Unmanaged profile fields (RIP, NTP option, option 15, ping conflict detection, sequential IP) keep " +
			"their device values on edit and get the UI's defaults on create.",
		Attributes: map[string]schema.Attribute{
			"vlan_id": schema.Int64Attribute{
				Required:      true,
				Description:   "VLAN ID.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"name":               schema.StringAttribute{Required: true, Description: "Profile name."},
			"inter_vlan_routing": schema.BoolAttribute{Required: true, Description: "Allow routing to other VLANs (subject to traffic rules)."},
			"device_management":  schema.BoolAttribute{Required: true, Description: "Whether the router's own admin UI is reachable from this VLAN."},
			"ip_address":         schema.StringAttribute{Required: true, Description: "The router's address on this VLAN (the gateway)."},
			"netmask":            schema.StringAttribute{Required: true, Description: "Subnet mask, e.g. 255.255.255.0."},
			"dhcp_enabled":       schema.BoolAttribute{Required: true, Description: "Whether the router serves DHCP on this VLAN."},
			"dhcp_start":         schema.StringAttribute{Required: true, Description: "First address of the DHCP pool."},
			"dhcp_end":           schema.StringAttribute{Required: true, Description: "Last address of the DHCP pool."},
			"dhcp_lease_seconds": schema.Int64Attribute{Required: true, Description: "DHCP lease time in seconds (the UI sets whole minutes)."},
			"dns_servers": schema.ListAttribute{
				Required: true, ElementType: types.StringType,
				Description: "DNS servers handed out by DHCP (option 6), in order.",
			},
			"domain_name": schema.StringAttribute{Required: true, Description: "DHCP domain name (option 15)."},
			"tagged_ports": schema.ListAttribute{
				Optional: true, ElementType: types.Int64Type,
				Description: "LAN ports (1-5) carrying this VLAN tagged.",
			},
			"untagged_ports": schema.ListAttribute{
				Optional: true, ElementType: types.Int64Type,
				Description: "LAN ports (1-5) carrying this VLAN untagged.",
			},
		},
	}
}

func (r *pr60xVLANResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m *pr60xVLANModel) spec() pr60x.VLANSpec {
	s := pr60x.VLANSpec{
		VLANID:           m.VLANID.ValueInt64(),
		Name:             m.Name.ValueString(),
		InterVLANRouting: m.InterVLANRouting.ValueBool(),
		DeviceManagement: m.DeviceManagement.ValueBool(),
		IPAddress:        m.IPAddress.ValueString(),
		Netmask:          m.Netmask.ValueString(),
		DHCPEnabled:      m.DHCPEnabled.ValueBool(),
		DHCPStart:        m.DHCPStart.ValueString(),
		DHCPEnd:          m.DHCPEnd.ValueString(),
		DHCPLeaseSeconds: m.DHCPLeaseSeconds.ValueInt64(),
		DomainName:       m.DomainName.ValueString(),
	}
	for _, d := range m.DNSServers {
		s.DNSServers = append(s.DNSServers, d.ValueString())
	}
	for _, p := range m.TaggedPorts {
		s.Ports = append(s.Ports, pr60x.VLANPort{Port: p.ValueInt64(), Type: "tagged"})
	}
	for _, p := range m.UntaggedPorts {
		s.Ports = append(s.Ports, pr60x.VLANPort{Port: p.ValueInt64(), Type: "untagged"})
	}
	return s
}

func (m *pr60xVLANModel) fromSpec(s *pr60x.VLANSpec) {
	m.VLANID = types.Int64Value(s.VLANID)
	m.Name = types.StringValue(s.Name)
	m.InterVLANRouting = types.BoolValue(s.InterVLANRouting)
	m.DeviceManagement = types.BoolValue(s.DeviceManagement)
	m.IPAddress = types.StringValue(s.IPAddress)
	m.Netmask = types.StringValue(s.Netmask)
	m.DHCPEnabled = types.BoolValue(s.DHCPEnabled)
	m.DHCPStart = types.StringValue(s.DHCPStart)
	m.DHCPEnd = types.StringValue(s.DHCPEnd)
	m.DHCPLeaseSeconds = types.Int64Value(s.DHCPLeaseSeconds)
	m.DomainName = types.StringValue(s.DomainName)
	m.DNSServers = nil
	for _, d := range s.DNSServers {
		m.DNSServers = append(m.DNSServers, types.StringValue(d))
	}
	var tagged, untagged []types.Int64
	for _, p := range s.Ports {
		// The router lists every LAN port on every VLAN; non-members are "excluded".
		switch p.Type {
		case "tagged":
			tagged = append(tagged, types.Int64Value(p.Port))
		case "untagged":
			untagged = append(untagged, types.Int64Value(p.Port))
		}
	}
	// Keep null vs empty consistent with configuration: an omitted list reads back as null.
	if len(tagged) > 0 || m.TaggedPorts != nil {
		m.TaggedPorts = tagged
	}
	if len(untagged) > 0 || m.UntaggedPorts != nil {
		m.UntaggedPorts = untagged
	}
}

func (r *pr60xVLANResource) readInto(m *pr60xVLANModel, diags *diag.Diagnostics) bool {
	got, err := r.client.GetVLAN(m.VLANID.ValueInt64())
	if err != nil {
		diags.AddError("Could not read VLAN", err.Error())
		return false
	}
	if got == nil {
		return false
	}
	m.fromSpec(got)
	return true
}

func (r *pr60xVLANResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan pr60xVLANModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	existing, err := r.client.GetVLAN(plan.VLANID.ValueInt64())
	if err != nil {
		resp.Diagnostics.AddError("Could not read VLANs", err.Error())
		return
	}
	if existing != nil {
		resp.Diagnostics.AddError("VLAN already exists",
			fmt.Sprintf("VLAN %d is already on the router. Import it instead: terraform import <addr> %d",
				plan.VLANID.ValueInt64(), plan.VLANID.ValueInt64()))
		return
	}
	if err := r.client.AddVLAN(plan.spec()); err != nil {
		resp.Diagnostics.AddError("Could not create VLAN", err.Error())
		return
	}
	if !r.readInto(&plan, &resp.Diagnostics) {
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError("VLAN not present after create",
				"addVlanProfiles reported success but the VLAN does not read back.")
		}
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *pr60xVLANResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state pr60xVLANModel
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

func (r *pr60xVLANResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan pr60xVLANModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.EditVLAN(plan.spec()); err != nil {
		resp.Diagnostics.AddError("Could not update VLAN", err.Error())
		return
	}
	r.readInto(&plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *pr60xVLANResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state pr60xVLANModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.VLANID.ValueInt64() == 1 {
		resp.Diagnostics.AddWarning("VLAN 1 left in place",
			"VLAN 1 is the LAN and is never deleted. Terraform has stopped managing it.")
		return
	}
	if err := r.client.DeleteVLAN(state.VLANID.ValueInt64()); err != nil {
		resp.Diagnostics.AddError("Could not delete VLAN", err.Error())
	}
}

func (r *pr60xVLANResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, err := strconv.ParseInt(req.ID, 10, 64)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("Expected a numeric VLAN id, got %q.", req.ID))
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vlan_id"), id)...)
}
