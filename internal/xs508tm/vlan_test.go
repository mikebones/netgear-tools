package xs508tm

import (
	"reflect"
	"testing"
)

// Real `show vlan 30` output from an XS508TM, firmware 7.8.11.21 (trimmed).
const showVLAN30 = `
VLAN ID: 30
VLAN Name: iot
VLAN Type: Static

Interface   Current   Configured   Tagging
----------  --------  -----------  --------
xg1         Exclude   Autodetect   Untagged
xg2         Exclude   Autodetect   Untagged
xg8         Exclude   Autodetect   Untagged
xg9         Include   Include      Tagged
xg10        Include   Include      Tagged
lag 1       Exclude   Autodetect   Untagged

(XS508TM)#`

func TestParseShowVLAN(t *testing.T) {
	v, ok := parseShowVLAN(30, showVLAN30)
	if !ok {
		t.Fatal("expected VLAN to parse")
	}
	if v.Name != "iot" {
		t.Errorf("name = %q", v.Name)
	}
	if !reflect.DeepEqual(v.TaggedPorts, []int{9, 10}) {
		t.Errorf("tagged = %v", v.TaggedPorts)
	}
}

func TestParseShowVLANMissing(t *testing.T) {
	if _, ok := parseShowVLAN(31, "ERROR! VLAN ID does not exist.\n"); ok {
		t.Error("missing VLAN parsed as present")
	}
}
