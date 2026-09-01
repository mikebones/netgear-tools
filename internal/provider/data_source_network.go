package provider

import (
	"netgear-tools/internal/pr60x"

	"context"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// This file holds the read-only network-state data sources: VLAN profiles,
// DHCP leases and WAN status. They are grouped because none of them is
// writable through this provider and each is small.

// --- VLAN profiles ---------------------------------------------------------

var _ datasource.DataSource = &vlanProfilesDataSource{}

type vlanProfilesDataSource struct{ client *pr60x.Client }

func NewVLANProfilesDataSource() datasource.DataSource { return &vlanProfilesDataSource{} }

type vlanProfileModel struct {
	VLANID               types.Int64  `tfsdk:"vlan_id"`
	Name                 types.String `tfsdk:"name"`
	Enabled              types.Bool   `tfsdk:"enabled"`
	IPAddress            types.String `tfsdk:"ip_address"`
	Netmask              types.String `tfsdk:"netmask"`
	DHCPServerEnabled    types.Bool   `tfsdk:"dhcp_server_enabled"`
	DHCPStartIPv4Address types.String `tfsdk:"dhcp_start_ip"`
	DHCPEndIPv4Address   types.String `tfsdk:"dhcp_end_ip"`
	DHCPLeaseTime        types.Int64  `tfsdk:"dhcp_lease_time"`
	DHCPDNSServers       types.List   `tfsdk:"dhcp_dns_servers"`
	DHCPDomainName       types.String `tfsdk:"dhcp_domain_name"`
}

type vlanProfilesModel struct {
	Profiles []vlanProfileModel `tfsdk:"profiles"`
}

func (d *vlanProfilesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_vlan_profiles"
}

func (d *vlanProfilesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "VLANs defined on the router, including each one's DHCP server settings. Read-only: VLAN and " +
			"DHCP changes can partition the network from the machine applying them, so they are deliberately not " +
			"manageable through this provider.",
		Attributes: map[string]schema.Attribute{
			"profiles": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"vlan_id":    schema.Int64Attribute{Computed: true},
						"name":       schema.StringAttribute{Computed: true},
						"enabled":    schema.BoolAttribute{Computed: true},
						"ip_address": schema.StringAttribute{Computed: true, Description: "The router's own address on this VLAN."},
						"netmask":    schema.StringAttribute{Computed: true},
						"dhcp_server_enabled": schema.BoolAttribute{
							Computed: true,
							Description: "Whether the ROUTER is serving DHCP on this VLAN. Worth asserting on if " +
								"something else on the segment is meant to own DHCP.",
						},
						"dhcp_start_ip":    schema.StringAttribute{Computed: true},
						"dhcp_end_ip":      schema.StringAttribute{Computed: true},
						"dhcp_lease_time":  schema.Int64Attribute{Computed: true, Description: "Seconds."},
						"dhcp_dns_servers": schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: "DHCP option 6, in order."},
						"dhcp_domain_name": schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

func (d *vlanProfilesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.PR60X == nil {
		resp.Diagnostics.AddError("PR60X not configured",
			"This data source reads the router. Add a `pr60x` block to the provider, or set PR60X_PASSWORD.")
		return
	}
	d.client = c.PR60X
}

func (d *vlanProfilesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	all, err := d.client.ListVLANProfiles()
	if err != nil {
		resp.Diagnostics.AddError("Could not read VLAN profiles", err.Error())
		return
	}

	state := vlanProfilesModel{Profiles: make([]vlanProfileModel, 0, len(all))}
	for _, v := range all {
		dns, diags := types.ListValueFrom(ctx, types.StringType, v.IPv4Settings.DHCPDNSAddr)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Profiles = append(state.Profiles, vlanProfileModel{
			VLANID:               types.Int64Value(v.VLANID),
			Name:                 types.StringValue(v.Name),
			Enabled:              types.BoolValue(v.Enabled != 0),
			IPAddress:            types.StringValue(v.IPv4Settings.IPAddress),
			Netmask:              types.StringValue(v.IPv4Settings.Netmask),
			DHCPServerEnabled:    types.BoolValue(v.IPv4Settings.DHCPServerEnabled != 0),
			DHCPStartIPv4Address: types.StringValue(v.IPv4Settings.DHCPStartIPv4Address),
			DHCPEndIPv4Address:   types.StringValue(v.IPv4Settings.DHCPEndIPv4Address),
			DHCPLeaseTime:        types.Int64Value(v.IPv4Settings.DHCPLeaseTime),
			DHCPDNSServers:       dns,
			DHCPDomainName:       types.StringValue(v.IPv4Settings.DHCPDomainName),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// --- DHCP leases -----------------------------------------------------------

var _ datasource.DataSource = &dhcpLeasesDataSource{}

type dhcpLeasesDataSource struct{ client *pr60x.Client }

func NewDHCPLeasesDataSource() datasource.DataSource { return &dhcpLeasesDataSource{} }

type dhcpLeaseModel struct {
	VLAN            types.String `tfsdk:"vlan"`
	HostName        types.String `tfsdk:"host_name"`
	IPAddress       types.String `tfsdk:"ip_address"`
	MACAddress      types.String `tfsdk:"mac_address"`
	LeaseExpireTime types.Int64  `tfsdk:"lease_expire_time"`
	Type            types.String `tfsdk:"type"`
}

type dhcpLeasesModel struct {
	Leases []dhcpLeaseModel `tfsdk:"leases"`
}

func (d *dhcpLeasesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_dhcp_leases"
}

func (d *dhcpLeasesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Current DHCP leases held by the router, flattened across VLANs. A free LAN inventory, and the " +
			"quickest way to spot a second DHCP server handing out overlapping addresses.",
		Attributes: map[string]schema.Attribute{
			"leases": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"vlan":              schema.StringAttribute{Computed: true, Description: "VLAN key as the device reports it, e.g. VLAN1."},
						"host_name":         schema.StringAttribute{Computed: true},
						"ip_address":        schema.StringAttribute{Computed: true},
						"mac_address":       schema.StringAttribute{Computed: true},
						"lease_expire_time": schema.Int64Attribute{Computed: true, Description: "Seconds remaining."},
						"type":              schema.StringAttribute{Computed: true, Description: "dynamic or static."},
					},
				},
			},
		},
	}
}

func (d *dhcpLeasesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.PR60X == nil {
		resp.Diagnostics.AddError("PR60X not configured",
			"This data source reads the router. Add a `pr60x` block to the provider, or set PR60X_PASSWORD.")
		return
	}
	d.client = c.PR60X
}

func (d *dhcpLeasesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	byVLAN, err := d.client.ListDHCPLeases()
	if err != nil {
		resp.Diagnostics.AddError("Could not read DHCP leases", err.Error())
		return
	}

	vlans := make([]string, 0, len(byVLAN))
	for k := range byVLAN {
		vlans = append(vlans, k)
	}
	sort.Strings(vlans)

	state := dhcpLeasesModel{Leases: []dhcpLeaseModel{}}
	for _, vlan := range vlans {
		leases := byVLAN[vlan]
		sort.Slice(leases, func(i, j int) bool { return leases[i].IPAddr < leases[j].IPAddr })
		for _, l := range leases {
			state.Leases = append(state.Leases, dhcpLeaseModel{
				VLAN:            types.StringValue(vlan),
				HostName:        types.StringValue(l.HostName),
				IPAddress:       types.StringValue(l.IPAddr),
				MACAddress:      types.StringValue(l.MACAddr),
				LeaseExpireTime: types.Int64Value(l.LeaseExpireTime),
				Type:            types.StringValue(l.Type),
			})
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// --- WAN status ------------------------------------------------------------

var _ datasource.DataSource = &wanStatusDataSource{}

type wanStatusDataSource struct{ client *pr60x.Client }

func NewWANStatusDataSource() datasource.DataSource { return &wanStatusDataSource{} }

type wanStatusModel struct {
	Status     types.String `tfsdk:"status"`
	WANType    types.String `tfsdk:"wan_type"`
	PublicIPs  types.List   `tfsdk:"public_ip_addresses"`
	PrimaryIP  types.String `tfsdk:"primary_public_ip"`
	Connected  types.Bool   `tfsdk:"connected"`
	IPRevision types.Int64  `tfsdk:"public_ip_count"`
}

func (d *wanStatusDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pr60x_wan_status"
}

func (d *wanStatusDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Current WAN connectivity and public address. Useful for asserting that dynamic DNS is " +
			"publishing the address the router actually holds.",
		Attributes: map[string]schema.Attribute{
			"status":              schema.StringAttribute{Computed: true, Description: "e.g. connected."},
			"connected":           schema.BoolAttribute{Computed: true, Description: "Convenience form of status."},
			"wan_type":            schema.StringAttribute{Computed: true, Description: "e.g. dhcp, static, pppoe."},
			"public_ip_addresses": schema.ListAttribute{Computed: true, ElementType: types.StringType},
			"primary_public_ip":   schema.StringAttribute{Computed: true, Description: "First entry, or empty if none."},
			"public_ip_count":     schema.Int64Attribute{Computed: true},
		},
	}
}

func (d *wanStatusDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c := clientsFrom(req.ProviderData)
	if c == nil {
		return
	}
	if c.PR60X == nil {
		resp.Diagnostics.AddError("PR60X not configured",
			"This data source reads the router. Add a `pr60x` block to the provider, or set PR60X_PASSWORD.")
		return
	}
	d.client = c.PR60X
}

func (d *wanStatusDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	st, err := d.client.GetWANStatus()
	if err != nil {
		resp.Diagnostics.AddError("Could not read WAN status", err.Error())
		return
	}

	ips, diags := types.ListValueFrom(ctx, types.StringType, st.PublicIPs)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	primary := ""
	if len(st.PublicIPs) > 0 {
		primary = st.PublicIPs[0]
	}

	state := wanStatusModel{
		Status:     types.StringValue(st.Status),
		Connected:  types.BoolValue(st.Status == "connected"),
		WANType:    types.StringValue(st.WANType),
		PublicIPs:  ips,
		PrimaryIP:  types.StringValue(primary),
		IPRevision: types.Int64Value(int64(len(st.PublicIPs))),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
