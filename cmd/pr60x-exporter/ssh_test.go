package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// sampleSSH is the batch output in the exact shape an OpenWrt ash shell prints.
// Values are synthetic; the structure is what the device emits.
const sampleSSH = `@@UPTIME
123456.78 987654.00
@@LOADAVG
0.15 0.22 0.31 1/128 4567
@@MEMINFO
MemTotal:         512000 kB
MemFree:          128000 kB
MemAvailable:     300000 kB
Cached:            64000 kB
@@NETDEV
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:    1000      10    0    0    0     0          0         0     1000      10    0    0    0     0       0          0
  eth1: 4294967296  67 1 2 0 0 0 0 500000 800 3 4 0 0 0 0
   br-lan: 900 9 0 0 0 0 0 0 800 8 0 0 0 0 0 0
  ifb0: 1 1 0 0 0 0 0 0 2 2 0 0 0 0 0 0
@@CTCOUNT
742
@@CTMAX
16384
16384
@@THERMAL
cpu-thermal 58200
nss-thermal 61000
@@LSMOD
Module                  Size  Used by
qca_nss_drv           500000  10
nf_conntrack          120000  5
@@QDISC
qdisc noqueue 0: dev lo root refcnt 2
qdisc cake 8011: dev eth1 root refcnt 2 bandwidth 100Mbit diffserv3
 Sent 500000 bytes 800 pkt (dropped 12, overlimits 34 requeues 0)
 backlog 1500b 3p requeues 0
 memory used: 128Kb of 4Mb
qdisc fq_codel 0: dev br-lan root refcnt 2
 Sent 900 bytes 8 pkt (dropped 0, overlimits 0 requeues 0)
 backlog 0b 0p requeues 0
@@WAN
{"up":true,"pending":false,"available":true,"autostart":true,"uptime":98765,"l3_device":"eth1"}
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

func TestParseSSH(t *testing.T) {
	reg := prometheus.NewRegistry()
	p := &sshPoller{m: newSSHMetrics(reg)}
	sec := splitSSHSections(sampleSSH)
	p.parseUptime(sec["UPTIME"])
	p.parseLoadavg(sec["LOADAVG"])
	p.parseMeminfo(sec["MEMINFO"])
	p.parseNetdev(sec["NETDEV"])
	p.parseConntrack(sec["CTCOUNT"], sec["CTMAX"])
	p.parseThermal(sec["THERMAL"])
	p.parseLsmod(sec["LSMOD"])
	p.parseQdisc(sec["QDISC"])
	p.parseWAN(sec["WAN"])

	mfs := gather(t, reg)

	// --- uptime / load / mem ---
	if v, ok := val(mfs["pr60x_proc_uptime_seconds"], nil); !ok || v != 123456.78 {
		t.Errorf("uptime = %v, %v; want 123456.78", v, ok)
	}
	if v, ok := val(mfs["pr60x_proc_load5"], nil); !ok || v != 0.22 {
		t.Errorf("load5 = %v, %v; want 0.22", v, ok)
	}
	if v, ok := val(mfs["pr60x_proc_memory_available_bytes"], nil); !ok || v != 300000*1024 {
		t.Errorf("memavailable = %v, %v; want %v", v, ok, 300000*1024)
	}

	// --- netdev: lo dropped; eth1 rx bytes exercises a value past 2^32 boundary ---
	if _, ok := val(mfs["pr60x_proc_interface_rx_bytes"], map[string]string{"interface": "lo"}); ok {
		t.Errorf("lo must not have a series")
	}
	if _, ok := val(mfs["pr60x_proc_interface_rx_bytes"], map[string]string{"interface": "ifb0"}); ok {
		t.Errorf("ifb0 (virtual noise) must not have a series")
	}
	if v, ok := val(mfs["pr60x_proc_interface_rx_bytes"], map[string]string{"interface": "eth1"}); !ok || v != 4294967296 {
		t.Errorf("eth1 rx bytes = %v, %v; want 4294967296", v, ok)
	}
	if v, ok := val(mfs["pr60x_proc_interface_tx_errors"], map[string]string{"interface": "eth1"}); !ok || v != 3 {
		t.Errorf("eth1 tx errors = %v, %v; want 3", v, ok)
	}
	if v, ok := val(mfs["pr60x_proc_interface_tx_drops"], map[string]string{"interface": "eth1"}); !ok || v != 4 {
		t.Errorf("eth1 tx drops = %v, %v; want 4", v, ok)
	}

	// --- conntrack ---
	if v, ok := val(mfs["pr60x_conntrack_count"], nil); !ok || v != 742 {
		t.Errorf("conntrack count = %v, %v; want 742", v, ok)
	}
	if v, ok := val(mfs["pr60x_conntrack_max"], nil); !ok || v != 16384 {
		t.Errorf("conntrack max = %v, %v; want 16384", v, ok)
	}

	// --- thermal: millidegrees -> C ---
	if v, ok := val(mfs["pr60x_thermal_temperature_celsius"], map[string]string{"zone": "cpu-thermal"}); !ok || v != 58.2 {
		t.Errorf("cpu-thermal = %v, %v; want 58.2", v, ok)
	}

	// --- lsmod: drv loaded, ecm absent -> 0 (still emitted) ---
	if v, ok := val(mfs["pr60x_nss_module_loaded"], map[string]string{"module": "qca_nss_drv"}); !ok || v != 1 {
		t.Errorf("qca_nss_drv loaded = %v, %v; want 1", v, ok)
	}
	if v, ok := val(mfs["pr60x_nss_module_loaded"], map[string]string{"module": "qca_nss_ecm"}); !ok || v != 0 {
		t.Errorf("qca_nss_ecm loaded = %v, %v; want 0 (absent)", v, ok)
	}

	// --- qdisc: cake on eth1 with drops/overlimits/backlog ---
	if _, ok := val(mfs["pr60x_qdisc_info"], map[string]string{"interface": "eth1", "kind": "cake"}); !ok {
		t.Errorf("cake qdisc on eth1 not found")
	}
	if v, ok := val(mfs["pr60x_qdisc_sent_bytes"], map[string]string{"interface": "eth1"}); !ok || v != 500000 {
		t.Errorf("eth1 qdisc sent bytes = %v, %v; want 500000", v, ok)
	}
	if v, ok := val(mfs["pr60x_qdisc_dropped_packets"], map[string]string{"interface": "eth1"}); !ok || v != 12 {
		t.Errorf("eth1 qdisc dropped = %v, %v; want 12", v, ok)
	}
	if v, ok := val(mfs["pr60x_qdisc_overlimits"], map[string]string{"interface": "eth1"}); !ok || v != 34 {
		t.Errorf("eth1 qdisc overlimits = %v, %v; want 34", v, ok)
	}
	if v, ok := val(mfs["pr60x_qdisc_backlog_bytes"], map[string]string{"interface": "eth1"}); !ok || v != 1500 {
		t.Errorf("eth1 qdisc backlog bytes = %v, %v; want 1500", v, ok)
	}
	if v, ok := val(mfs["pr60x_qdisc_backlog_packets"], map[string]string{"interface": "eth1"}); !ok || v != 3 {
		t.Errorf("eth1 qdisc backlog packets = %v, %v; want 3", v, ok)
	}

	// --- wan (ubus) ---
	if v, ok := val(mfs["pr60x_wan_up"], nil); !ok || v != 1 {
		t.Errorf("wan up = %v, %v; want 1", v, ok)
	}
	if v, ok := val(mfs["pr60x_wan_uptime_seconds"], nil); !ok || v != 98765 {
		t.Errorf("wan uptime = %v, %v; want 98765", v, ok)
	}
}
