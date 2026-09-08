package main

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Sample /proc output in the exact shape the RTL93xx driver prints. Serial-
// number bytes in the optical EEPROM are neutralised (this repo is public); the
// structure is byte-for-byte what the device emits.
const sampleProc = `@@POE

PoE Initial Result : Success.. (0)


===== PoE Global Information =====

Board ID        : 0
Power Budget    : 280200 mW
Power Consumed  :  43200 mW


===== PoE Port Information (Delivering Power) =====

| Port |   Power   | Max Power | Class | Description
|------|-----------|-----------|-------|---------------------------------------
   1        5400       31200       4     Powering up with 'bt-type3', max power limit is 'Class-based'.
   5       10100       51000       6     Powering up with 'bt-type3', max power limit is 'Negotiated via LLDP'.


===== PoE Port Information (Others) =====

| Port | Status  | Startup-Mode | Max Power
|------|---------|--------------|------------
   6     Search       bt-type3    class-based
   7     Search       bt-type3    class-based


===== PoE Port Status Logs =====

----- Port  1 -----
[  0 day,  0 hour,  0 min, 35 sec] Power Up. Current power is 6000 mW.
--------------------
@@LINKDOWN
port MultiGigabitEthernet3 (cur: 0):
  tmp reason:
    1767225609.120000000 (3)SW-AdminDown
  reason log:
    0.000000000 (0)Unknown
    0.000000000 (0)Unknown

port MultiGigabitEthernet4 (cur: 1):
  tmp reason:
    1767225609.120000000 (3)SW-AdminDown
  reason log:
    1767225610.470000000 (3)SW-AdminDown
    0.000000000 (0)Unknown
    0.000000000 (0)Unknown

@@OPTICAL

Port xg9:
000: 03 04 21 00 00 00 00 00    04 00 00 00 67 00 00 00        ..!..... ....g...
016: 00 00 01 00 4f 45 4d 20    20 20 20 20 20 20 20 20        ....OEM
032: 20 20 20 20 00 00 40 20    53 46 50 2d 48 31 30 47            ..@  SFP-H10G
048: 42 2d 43 55 30 2e 35 4d    30 33 20 20 01 00 00 06        B-CU0.5M 03  ....
064: 00 00 00 00 30 30 30 30    30 30 30 30 30 30 20 20        ....0000 000000
080: 20 20 20 20 30 30 30 30    30 30 20 20 00 00 00 2a            0000 00  ...*
096: 80 00 11 ba 10 2c 2a 78    0e fc 5a 28 a6 73 34 23        .....,*x ..Z(.s4#
112: 9d 5c 9d 3f cc 00 00 00    00 00 f9 a8 49 80 5e 12        .\.?.... ....I.^.
@@DONE
`

func gather(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]*dto.MetricFamily{}
	for _, mf := range mfs {
		out[mf.GetName()] = mf
	}
	return out
}

// val returns the gauge value for a metric with the given label values.
func val(mf *dto.MetricFamily, want map[string]string) (float64, bool) {
	if mf == nil {
		return 0, false
	}
	for _, m := range mf.GetMetric() {
		labels := map[string]string{}
		for _, l := range m.GetLabel() {
			labels[l.GetName()] = l.GetValue()
		}
		match := true
		for k, v := range want {
			if labels[k] != v {
				match = false
				break
			}
		}
		if match {
			return m.GetGauge().GetValue(), true
		}
	}
	return 0, false
}

func TestParseProc(t *testing.T) {
	reg := prometheus.NewRegistry()
	p := &sshPoller{m: newSSHMetrics(reg)}
	sec := splitSSHSections(sampleProc)
	p.parsePoE(sec["POE"])
	p.parseLinkdown(sec["LINKDOWN"])
	p.parseOptical(sec["OPTICAL"])

	mfs := gather(t, reg)

	// --- PoE ---
	if v, ok := val(mfs["ms510txup_proc_poe_budget_milliwatts"], nil); !ok || v != 280200 {
		t.Errorf("poe budget = %v, %v; want 280200", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_poe_consumed_milliwatts"], nil); !ok || v != 43200 {
		t.Errorf("poe consumed = %v, %v; want 43200", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_poe_port_power_milliwatts"], map[string]string{"port": "5"}); !ok || v != 10100 {
		t.Errorf("poe port5 power = %v, %v; want 10100", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_poe_port_class"], map[string]string{"port": "5"}); !ok || v != 6 {
		t.Errorf("poe port5 class = %v, %v; want 6", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_poe_port_delivering"], map[string]string{"port": "1"}); !ok || v != 1 {
		t.Errorf("poe port1 delivering = %v, %v; want 1", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_poe_port_delivering"], map[string]string{"port": "6"}); !ok || v != 0 {
		t.Errorf("poe port6 delivering = %v, %v; want 0 (searching)", v, ok)
	}

	// --- linkdown: port 4 has one real reason, port 3 has none ---
	if v, ok := val(mfs["ms510txup_proc_port_linkdown_logged_events"], map[string]string{"port": "4"}); !ok || v != 1 {
		t.Errorf("linkdown port4 events = %v, %v; want 1", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_port_linkdown_logged_events"], map[string]string{"port": "3"}); !ok || v != 0 {
		t.Errorf("linkdown port3 events = %v, %v; want 0", v, ok)
	}
	if _, ok := val(mfs["ms510txup_proc_port_linkdown_reason_info"], map[string]string{"port": "4", "reason": "SW-AdminDown"}); !ok {
		t.Errorf("linkdown port4 reason SW-AdminDown not found")
	}
	if _, ok := val(mfs["ms510txup_proc_port_linkdown_reason_info"], map[string]string{"port": "3", "reason": "none"}); !ok {
		t.Errorf("linkdown port3 reason 'none' not found")
	}

	// --- optical: xg9 present, DAC has no DDM, part decoded ---
	if v, ok := val(mfs["ms510txup_proc_sfp_present"], map[string]string{"port": "9"}); !ok || v != 1 {
		t.Errorf("sfp port9 present = %v, %v; want 1", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_sfp_ddm_supported"], map[string]string{"port": "9"}); !ok || v != 0 {
		t.Errorf("sfp port9 ddm = %v, %v; want 0 (DAC)", v, ok)
	}
	if _, ok := val(mfs["ms510txup_proc_sfp_info"], map[string]string{"port": "9", "vendor": "OEM", "part_number": "SFP-H10GB-CU0.5M"}); !ok {
		t.Errorf("sfp port9 info (OEM / SFP-H10GB-CU0.5M) not found")
	}
}

func TestPortNumFromName(t *testing.T) {
	cases := map[string]string{
		"port MultiGigabitEthernet4 (cur: 1):": "4",
		"port XGigabitEthernet10 (cur: 0):":    "10",
		"Port xg9:":                            "9",
		"Port xg10:":                           "10",
	}
	for in, want := range cases {
		if got := portNumFromName(strings.TrimSpace(in)); got != want {
			t.Errorf("portNumFromName(%q) = %q; want %q", in, got, want)
		}
	}
}
