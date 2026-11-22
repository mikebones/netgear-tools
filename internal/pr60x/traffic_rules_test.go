package pr60x

import "testing"

func TestParseAddressRoundTrip(t *testing.T) {
	for _, s := range []string{"any", "192.0.2.53", "198.51.100.0/24", "198.51.100.10-198.51.100.49"} {
		a, err := ParseAddress(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if a.String() != s {
			t.Errorf("round trip %q -> %q", s, a.String())
		}
	}
	if _, err := ParseAddress("not-an-ip"); err == nil {
		t.Error("expected error for garbage")
	}
}

func TestPayloadMatchesUIShape(t *testing.T) {
	r := TrafficRule{Name: "x", Allow: true, Enabled: true, Service: "DNS-UDP", Schedule: "Always",
		SourceInterface: "vlan30", DestinationInterface: "lan",
		Source: Address{Type: "Subnet", IP: "198.51.100.0", Prefix: 24}, Destination: Address{Type: "Single", IP: "192.0.2.53"}}
	p := r.payload()
	want := map[string]any{"action": "Allow", "sourceAddressType": "Subnet", "sourceIpV4Address": "198.51.100.0",
		"sourceSubnetRange": int64(24), "destinationAddressType": "Single", "destinationIpV4Address": "192.0.2.53", "enabled": int64(1)}
	for k, v := range want {
		if p[k] != v {
			t.Errorf("%s = %v, want %v", k, p[k], v)
		}
	}
}

func TestNormalizeInterface(t *testing.T) {
	for in, want := range map[string]string{"VLAN30": "vlan30", "WAN": "wan", "Any": "Any", "VLAN1": "lan", "lan": "lan"} {
		if got := normalizeInterface(in); got != want {
			t.Errorf("%s -> %s, want %s", in, got, want)
		}
	}
}
