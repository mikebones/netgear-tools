package xs508tm

import (
	"reflect"
	"testing"
)

// Representative FASTPATH `show vlan <id>` output (NETGEAR smart/managed CLI).
const showVLAN30 = `
VLAN ID........................................ 30
VLAN Name...................................... iot
VLAN Type...................................... Static

Interface   Current   Configured   Tagging
----------  --------  -----------  --------
0/1         Exclude   Exclude      Untagged
0/2         Include   Include      Tagged
0/3         Exclude   Exclude      Untagged
0/8         Include   Include      Tagged
0/9         Exclude   Autodetect   Untagged
`

func TestParseShowVLAN(t *testing.T) {
	v, ok := parseShowVLAN(30, showVLAN30)
	if !ok {
		t.Fatal("expected VLAN to parse")
	}
	if v.Name != "iot" {
		t.Errorf("name = %q", v.Name)
	}
	if !reflect.DeepEqual(v.TaggedPorts, []int{2, 8}) {
		t.Errorf("tagged = %v", v.TaggedPorts)
	}
}

func TestParseShowVLANMissing(t *testing.T) {
	if _, ok := parseShowVLAN(31, "ERROR! VLAN ID does not exist.\n"); ok {
		t.Error("missing VLAN parsed as present")
	}
}
