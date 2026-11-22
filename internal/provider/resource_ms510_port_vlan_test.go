package provider

import (
	"reflect"
	"testing"
)

func TestParseVLANList(t *testing.T) {
	cases := map[string][]int64{
		"":         nil,
		"1":        {1},
		"30,1":     {1, 30},
		"1-3,20":   {1, 2, 3, 20},
		" 1 , 30 ": {1, 30},
	}
	for in, want := range cases {
		got, err := parseVLANList(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v want %v", in, got, want)
		}
		if back, _ := parseVLANList(formatVLANList(got)); !reflect.DeepEqual(back, want) {
			t.Errorf("%q: round trip gave %v", in, back)
		}
	}
	for _, bad := range []string{"x", "3-1", "1-x"} {
		if _, err := parseVLANList(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}
