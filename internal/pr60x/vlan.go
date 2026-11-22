package pr60x

import (
	"fmt"
	"sort"
)

// --- VLAN profiles (create / edit / delete) ---------------------------------
//
// Method names and the profile shape come from the router's own UI bundle
// (static/js/main.*.js, firmware 3.0.0.105): addVlanProfiles, editVlanProfiles,
// deleteVlanProfiles; the UI builds the same object getVlanProfiles returns.
// Collection setters on this device take an ARRAY of objects carrying an
// "action" discriminator (see SetVLANDHCPDNS, verified), so the same calling
// convention is used here.
//
// Edits are read-modify-write on the raw map, for the reason given at
// GetVLANProfilesRaw: the profile carries fields nothing here models.

// VLANPort is one LAN port's membership. Ports are the router's front-panel
// LAN numbers 1-5 (lan1..lan5); type is "tagged" or "untagged".
type VLANPort struct {
	Port int64  `json:"port"`
	Type string `json:"type"`
}

// VLANSpec is everything the provider manages on a VLAN profile.
type VLANSpec struct {
	VLANID           int64
	Name             string
	InterVLANRouting bool
	DeviceManagement bool
	IPAddress        string
	Netmask          string
	DHCPEnabled      bool
	DHCPStart        string
	DHCPEnd          string
	DHCPLeaseSeconds int64
	DNSServers       []string
	DomainName       string
	Ports            []VLANPort
}

func b2i(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// portsToAny lists all five LAN ports, as the device does: members as
// tagged/untagged, everything else "excluded".
func portsToAny(ports []VLANPort) []any {
	byPort := map[int64]string{}
	for _, p := range ports {
		byPort[p.Port] = p.Type
	}
	for port := int64(1); port <= 5; port++ {
		if _, ok := byPort[port]; !ok {
			ports = append(ports, VLANPort{Port: port, Type: "excluded"})
		}
	}
	sorted := append([]VLANPort(nil), ports...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Port < sorted[j].Port })
	out := make([]any, 0, len(sorted))
	for _, p := range sorted {
		out = append(out, map[string]any{"port": p.Port, "type": p.Type})
	}
	return out
}

func stringsToAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

// overlay writes the managed fields of spec onto a raw profile map.
func (s VLANSpec) overlay(p map[string]any) {
	p["vlanId"] = s.VLANID
	p["name"] = s.Name
	p["enabled"] = int64(1)
	p["interVlanRouting"] = b2i(s.InterVLANRouting)
	p["deviceManagement"] = b2i(s.DeviceManagement)
	p["vlanPorts"] = portsToAny(s.Ports)

	ipv4, _ := p["ipv4Settings"].(map[string]any)
	if ipv4 == nil {
		ipv4 = map[string]any{}
		p["ipv4Settings"] = ipv4
	}
	ipv4["ipAddress"] = s.IPAddress
	ipv4["netmask"] = s.Netmask
	ipv4["dhcpServerEnabled"] = b2i(s.DHCPEnabled)
	ipv4["dhcpStartIpv4Address"] = s.DHCPStart
	ipv4["dhcpEndIpv4Address"] = s.DHCPEnd
	ipv4["dhcpLeaseTime"] = s.DHCPLeaseSeconds
	ipv4["dhcpDnsAddr"] = stringsToAny(s.DNSServers)
	if len(s.DNSServers) > 0 {
		ipv4["dhcpDnsType"] = "custom"
	}
	ipv4["dhcpDomainName"] = s.DomainName
}

// newProfile is a fresh profile with the UI's defaults for everything not
// managed here (values as the UI's add form submits them).
func newProfile() map[string]any {
	return map[string]any{
		"ipv4Settings": map[string]any{
			"sequentialIp":          int64(0),
			"dhcpNtpServerEnabled":  int64(0),
			"dhcpNtpServerAddr":     []any{},
			"pingConflictDetection": int64(1),
			"dhcpOption15Enabled":   int64(1),
			"dhcpDnsType":           "custom",
		},
		"rip": map[string]any{"direction": "Both", "version": "Disabled"},
	}
}

// AddVLAN creates a VLAN profile.
func (c *Client) AddVLAN(s VLANSpec) error {
	p := newProfile()
	s.overlay(p)
	p["action"] = "add"
	return c.Call("addVlanProfiles", []map[string]any{p}, nil)
}

// EditVLAN rewrites the managed fields of an existing profile, leaving every
// unmanaged field as the device returned it.
func (c *Client) EditVLAN(s VLANSpec) error {
	p, err := c.GetVLANProfileRaw(s.VLANID)
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("no VLAN with id %d", s.VLANID)
	}
	s.overlay(p)
	p["action"] = "edit"
	return c.Call("editVlanProfiles", []map[string]any{p}, nil)
}

// DeleteVLAN removes a VLAN profile. VLAN 1 is refused: it is the LAN.
func (c *Client) DeleteVLAN(vlanID int64) error {
	if vlanID == 1 {
		return fmt.Errorf("refusing to delete VLAN 1 (the default LAN)")
	}
	p, err := c.GetVLANProfileRaw(vlanID)
	if err != nil {
		return err
	}
	if p == nil {
		return nil
	}
	p["action"] = "delete"
	return c.Call("deleteVlanProfiles", []map[string]any{p}, nil)
}

// GetVLAN reads a profile into a VLANSpec. Returns nil, nil when absent.
func (c *Client) GetVLAN(vlanID int64) (*VLANSpec, error) {
	p, err := c.GetVLANProfileRaw(vlanID)
	if err != nil || p == nil {
		return nil, err
	}
	num := func(v any) int64 {
		switch t := v.(type) {
		case float64:
			return int64(t)
		case int64:
			return t
		}
		return 0
	}
	str := func(v any) string { s, _ := v.(string); return s }
	s := &VLANSpec{
		VLANID:           num(p["vlanId"]),
		Name:             str(p["name"]),
		InterVLANRouting: num(p["interVlanRouting"]) == 1,
		DeviceManagement: num(p["deviceManagement"]) == 1,
	}
	if ipv4, ok := p["ipv4Settings"].(map[string]any); ok {
		s.IPAddress = str(ipv4["ipAddress"])
		s.Netmask = str(ipv4["netmask"])
		s.DHCPEnabled = num(ipv4["dhcpServerEnabled"]) == 1
		s.DHCPStart = str(ipv4["dhcpStartIpv4Address"])
		s.DHCPEnd = str(ipv4["dhcpEndIpv4Address"])
		s.DHCPLeaseSeconds = num(ipv4["dhcpLeaseTime"])
		s.DomainName = str(ipv4["dhcpDomainName"])
		if raw, ok := ipv4["dhcpDnsAddr"].([]any); ok {
			for _, d := range raw {
				if ds, ok := d.(string); ok {
					s.DNSServers = append(s.DNSServers, ds)
				}
			}
		}
	}
	if raw, ok := p["vlanPorts"].([]any); ok {
		for _, e := range raw {
			m, _ := e.(map[string]any)
			s.Ports = append(s.Ports, VLANPort{Port: num(m["port"]), Type: str(m["type"])})
		}
	}
	sort.Slice(s.Ports, func(i, j int) bool { return s.Ports[i].Port < s.Ports[j].Port })
	return s, nil
}
