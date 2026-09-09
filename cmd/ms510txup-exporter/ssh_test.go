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
@@VLAN
vid(group id): utagged member| tagged member
1(1): mg1-4,xmg5-8,xg9-10 |
20(1):  | mg1-4,xg10
4086(0):  |
PVID
MultiGigabitEthernet1: 1
MultiGigabitEthernet2: 20
XGigabitEthernet10: 1
@@HWMON
phy:
  0.0 enabled: 0
portmib:
  mg4 enabled: 1, period: 10
  xg9 enabled: 1, period: 10
  xg10 enabled: 0
  lag1 enabled: 0
@@MIB
port mg4
0000: 1700000000.000000000 00000000 00000064 00000000 00000005 00000001 00000000 00000000 00000032 00000000 00000003 00000000 00001000
port xg9
0000: 1700000500.000000000 00000000 0000000A 00000000 00000002 00000000 00000BB8 00000000 00000014 00000000 00000004 00000000 00001770
port xg10
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
	p.parseVLAN(sec["VLAN"])
	p.parseHwmonStatus(sec["HWMON"])
	p.parseMIB(sec["MIB"])

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
	// port 4's most recent (and only) real entry timestamp; port 3 has none -> 0.
	if v, ok := val(mfs["ms510txup_proc_port_linkdown_last_timestamp_seconds"], map[string]string{"port": "4"}); !ok || v != 1767225610.47 {
		t.Errorf("linkdown port4 last ts = %v, %v; want 1767225610.47", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_port_linkdown_last_timestamp_seconds"], map[string]string{"port": "3"}); !ok || v != 0 {
		t.Errorf("linkdown port3 last ts = %v, %v; want 0", v, ok)
	}

	// --- hwmon.status: front-panel sampler enable flags (phy/lag skipped) ---
	if v, ok := val(mfs["ms510txup_proc_sampler_enabled"], map[string]string{"port": "4"}); !ok || v != 1 {
		t.Errorf("sampler_enabled port4 = %v, %v; want 1", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_sampler_enabled"], map[string]string{"port": "10"}); !ok || v != 0 {
		t.Errorf("sampler_enabled port10 = %v, %v; want 0", v, ok)
	}

	// --- portmib counters: mg4 (port 4) uses a hi word to exercise 64-bit combine ---
	if v, ok := val(mfs["ms510txup_proc_port_rx_packets"], map[string]string{"port": "4"}); !ok || v != 100 {
		t.Errorf("rx_packets port4 = %v, %v; want 100", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_port_rx_bytes"], map[string]string{"port": "4"}); !ok || v != 4294967296 {
		t.Errorf("rx_bytes port4 = %v, %v; want 4294967296 (0x1_00000000)", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_port_tx_bytes"], map[string]string{"port": "4"}); !ok || v != 4096 {
		t.Errorf("tx_bytes port4 = %v, %v; want 4096", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_port_rx_multicast_broadcast_packets"], map[string]string{"port": "4"}); !ok || v != 5 {
		t.Errorf("rx_mcast_bcast port4 = %v, %v; want 5", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_port_counter_sample_timestamp_seconds"], map[string]string{"port": "9"}); !ok || v != 1700000500 {
		t.Errorf("counter_sample_ts port9 = %v, %v; want 1700000500", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_port_tx_bytes"], map[string]string{"port": "9"}); !ok || v != 6000 {
		t.Errorf("tx_bytes port9 = %v, %v; want 6000", v, ok)
	}
	// port 10's sampler is disabled (no ring row), so there must be no counter series.
	if _, ok := val(mfs["ms510txup_proc_port_rx_packets"], map[string]string{"port": "10"}); ok {
		t.Errorf("rx_packets should have no series for port10 (sampler disabled)")
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

	// --- vlan: VLAN 1 untagged on all ports, VLAN 20 tagged on 1-4 and 10 ---
	if v, ok := val(mfs["ms510txup_proc_vlan_port_membership"], map[string]string{"vlan": "1", "port": "7"}); !ok || v != 1 {
		t.Errorf("vlan1 port7 membership = %v, %v; want 1 (untagged)", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_vlan_port_membership"], map[string]string{"vlan": "20", "port": "4"}); !ok || v != 2 {
		t.Errorf("vlan20 port4 membership = %v, %v; want 2 (tagged)", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_vlan_port_membership"], map[string]string{"vlan": "20", "port": "10"}); !ok || v != 2 {
		t.Errorf("vlan20 port10 membership = %v, %v; want 2 (tagged)", v, ok)
	}
	// Port 5 is not in VLAN 20, so there must be no series for it.
	if _, ok := val(mfs["ms510txup_proc_vlan_port_membership"], map[string]string{"vlan": "20", "port": "5"}); ok {
		t.Errorf("vlan20 should have no series for port5")
	}
	// PVID: port 2 was set to 20 in the fixture, port 1 stays on 1.
	if v, ok := val(mfs["ms510txup_proc_port_pvid"], map[string]string{"port": "2"}); !ok || v != 20 {
		t.Errorf("port2 pvid = %v, %v; want 20", v, ok)
	}
	if v, ok := val(mfs["ms510txup_proc_port_pvid"], map[string]string{"port": "1"}); !ok || v != 1 {
		t.Errorf("port1 pvid = %v, %v; want 1", v, ok)
	}
}

func TestExpandPortList(t *testing.T) {
	cases := map[string][]string{
		"mg1-4,xmg5-8,xg9-10": {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"},
		" mg1-4,xg10":         {"1", "2", "3", "4", "10"},
		"":                    nil,
		"  ":                  nil,
		"xg10":                {"10"},
	}
	for in, want := range cases {
		got := expandPortList(in)
		if len(got) != len(want) {
			t.Errorf("expandPortList(%q) = %v; want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("expandPortList(%q) = %v; want %v", in, got, want)
				break
			}
		}
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
