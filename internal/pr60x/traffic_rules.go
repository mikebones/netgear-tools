package pr60x

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// --- Traffic rules (firewall between interfaces) ----------------------------
//
// Verified against firmware 3.0.0.105 on 2026-11-22 with a disabled probe rule:
//
//   addTrafficRules([rule, ...])   rule as the UI submits it (below); result 0
//   getTrafficRules                list; interfaces come back UPPER-cased
//                                  ("VLAN30", "WAN"), the address type key is
//                                  renamed to sourceIpV4AddressType, enabled is
//                                  an int, and each rule gains an "id"
//   deleteTrafficRules([id, ...])  plain array of ids (what the UI sends)
//
// Interfaces are the router's interface ids: "lan" (VLAN 1), "vlan<N>", "wan",
// or "Any". A rule between two VLANs is refused ("Traffic Rule vlan30 and lan
// is not valid", rpc 1907) unless inter-VLAN routing is on for them.
//
// Order is priority: rules are evaluated top-down, so the list is replaced as
// a whole (delete all, add in order).

// Address is a rule endpoint: Any, a single IP, a subnet (CIDR) or a range.
type Address struct {
	Type   string // Any | Single | Subnet | Range
	IP     string // Single/Subnet: address; Range: start
	Prefix int64  // Subnet only
	End    string // Range only
}

// ParseAddress accepts "any", "1.2.3.4", "1.2.3.0/24" or "1.2.3.4-1.2.3.9".
func ParseAddress(s string) (Address, error) {
	s = strings.TrimSpace(s)
	switch {
	case strings.EqualFold(s, "any") || s == "":
		return Address{Type: "Any"}, nil
	case strings.Contains(s, "/"):
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			return Address{}, fmt.Errorf("bad subnet %q: %w", s, err)
		}
		ones, _ := n.Mask.Size()
		return Address{Type: "Subnet", IP: ip.String(), Prefix: int64(ones)}, nil
	case strings.Contains(s, "-"):
		parts := strings.SplitN(s, "-", 2)
		a, b := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if net.ParseIP(a) == nil || net.ParseIP(b) == nil {
			return Address{}, fmt.Errorf("bad range %q", s)
		}
		return Address{Type: "Range", IP: a, End: b}, nil
	default:
		if net.ParseIP(s) == nil {
			return Address{}, fmt.Errorf("bad address %q (want any, IP, CIDR or start-end)", s)
		}
		return Address{Type: "Single", IP: s}, nil
	}
}

// String is the inverse of ParseAddress.
func (a Address) String() string {
	switch a.Type {
	case "Single":
		return a.IP
	case "Subnet":
		return a.IP + "/" + strconv.FormatInt(a.Prefix, 10)
	case "Range":
		return a.IP + "-" + a.End
	}
	return "any"
}

// TrafficRule is one rule as the provider models it.
type TrafficRule struct {
	ID                   int64
	Name                 string
	Enabled              bool
	Allow                bool
	Service              string
	Schedule             string
	SourceInterface      string
	DestinationInterface string
	Source               Address
	Destination          Address
}

func putAddress(m map[string]any, side string, a Address) {
	m[side+"AddressType"] = a.Type
	switch a.Type {
	case "Any":
		m[side+"IpV4Address"] = "Any"
	case "Single":
		m[side+"IpV4Address"] = a.IP
	case "Subnet":
		m[side+"IpV4Address"] = a.IP
		m[side+"SubnetRange"] = a.Prefix
	case "Range":
		m["start"+side+"IpV4Address"] = a.IP
		m["end"+side+"IpV4Address"] = a.End
	}
}

func (r TrafficRule) payload() map[string]any {
	action := "Deny"
	if r.Allow {
		action = "Allow"
	}
	m := map[string]any{
		"name":                 r.Name,
		"enabled":              b2i(r.Enabled),
		"action":               action,
		"service":              r.Service,
		"schedule":             r.Schedule,
		"sourceInterface":      r.SourceInterface,
		"destinationInterface": r.DestinationInterface,
	}
	putAddress(m, "source", r.Source)
	putAddress(m, "destination", r.Destination)
	return m
}

func getAddress(m map[string]any, side string) Address {
	str := func(k string) string { s, _ := m[k].(string); return s }
	a := Address{Type: str(side + "IpV4AddressType")}
	if a.Type == "" {
		a.Type = str(side + "AddressType")
	}
	switch a.Type {
	case "Single":
		a.IP = str(side + "IpV4Address")
	case "Subnet":
		a.IP = str(side + "IpV4Address")
		if f, ok := m[side+"SubnetRange"].(float64); ok {
			a.Prefix = int64(f)
		} else if s := str(side + "SubnetRange"); s != "" {
			a.Prefix, _ = strconv.ParseInt(s, 10, 64)
		}
	case "Range":
		a.IP = str("start" + side + "IpV4Address")
		a.End = str("end" + side + "IpV4Address")
	default:
		a.Type = "Any"
	}
	return a
}

// normalizeInterface maps the device's read-back form ("VLAN30", "WAN") to the
// ids rules are written with ("vlan30", "wan"); "Any" stays "Any".
func normalizeInterface(s string) string {
	if strings.EqualFold(s, "any") {
		return "Any"
	}
	l := strings.ToLower(s)
	if l == "vlan1" {
		return "lan"
	}
	return l
}

// ListTrafficRules returns the rules in priority order.
func (c *Client) ListTrafficRules() ([]TrafficRule, error) {
	var raw []map[string]any
	if err := c.CallResult("getTrafficRules", map[string]any{}, &raw); err != nil {
		return nil, err
	}
	out := make([]TrafficRule, 0, len(raw))
	for _, m := range raw {
		str := func(k string) string { s, _ := m[k].(string); return s }
		enabled := false
		switch v := m["enabled"].(type) {
		case float64:
			enabled = v == 1
		case string:
			enabled = strings.EqualFold(v, "Enabled") || v == "1"
		}
		id, _ := m["id"].(float64)
		action := str("action")
		out = append(out, TrafficRule{
			ID:                   int64(id),
			Name:                 str("name"),
			Enabled:              enabled,
			Allow:                strings.HasPrefix(strings.ToLower(action), "allow"),
			Service:              str("service"),
			Schedule:             str("schedule"),
			SourceInterface:      normalizeInterface(str("sourceInterface")),
			DestinationInterface: normalizeInterface(str("destinationInterface")),
			Source:               getAddress(m, "source"),
			Destination:          getAddress(m, "destination"),
		})
	}
	return out, nil
}

// ReplaceTrafficRules makes the device's rule list exactly rules, in order.
// Existing rules are deleted first; there is a sub-second window with no rules.
func (c *Client) ReplaceTrafficRules(rules []TrafficRule) error {
	existing, err := c.ListTrafficRules()
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		ids := make([]any, 0, len(existing))
		for _, r := range existing {
			ids = append(ids, r.ID)
		}
		if err := c.Call("deleteTrafficRules", ids, nil); err != nil {
			return fmt.Errorf("delete existing rules: %w", err)
		}
	}
	if len(rules) == 0 {
		return nil
	}
	payload := make([]any, 0, len(rules))
	for _, r := range rules {
		payload = append(payload, r.payload())
	}
	if err := c.Call("addTrafficRules", payload, nil); err != nil {
		return fmt.Errorf("add rules: %w", err)
	}
	return nil
}
