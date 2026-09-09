package main

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// sampleSSH is the batch output in the shape the AP's shell prints: /proc reads,
// `iw dev`, then a per-interface station dump under a @@STA <iface> marker.
const sampleSSH = `@@UPTIME
54321.10 111111.00
@@LOADAVG
0.40 0.35 0.30 2/90 1234
@@MEMINFO
MemTotal:         900000 kB
MemFree:          400000 kB
MemAvailable:     600000 kB
Cached:           100000 kB
@@NETDEV
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   500 5 0 0 0 0 0 0 500 5 0 0 0 0 0 0
  wlan0: 111111 222 0 0 0 0 0 0 333333 444 0 0 0 0 0 0
  ifb5: 1 1 0 0 0 0 0 0 2 2 0 0 0 0 0 0
@@THERMAL
cpu-thermal 62500
@@IWDEV
phy#0
	Interface wlan0
		ifindex 12
		wdev 0x1
		addr aa:bb:cc:00:11:22
		ssid HomeLab-5G
		type AP
		channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz
		txpower 23.00 dBm
phy#1
	Interface wlan1
		ifindex 13
		ssid HomeLab-2G
		type AP
		channel 6 (2437 MHz), width: 20 MHz
		txpower 20.00 dBm
@@STA wlan0
Station de:ad:be:ef:00:01 (on wlan0)
	inactive time:	120 ms
	rx bytes:	123456
	rx packets:	789
	tx bytes:	654321
	tx packets:	456
	signal:  	-55 dBm
	signal avg:	-56 dBm
	tx bitrate:	866.7 MBit/s
	rx bitrate:	780.0 MBit/s
	connected time:	3600 seconds
Station de:ad:be:ef:00:02 (on wlan0)
	rx bytes:	1000
	tx bytes:	2000
	signal:  	-70 dBm
	tx bitrate:	200.0 MBit/s
	rx bitrate:	150.0 MBit/s
	connected time:	60 seconds
@@STA wlan1
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
	p.parseThermal(sec["THERMAL"])
	p.parseIWDev(sec["IWDEV"])
	p.parseStations(sec)

	mfs := gather(t, reg)

	// --- health ---
	if v, ok := val(mfs["wax630e_proc_uptime_seconds"], nil); !ok || v != 54321.10 {
		t.Errorf("uptime = %v, %v; want 54321.10", v, ok)
	}
	if v, ok := val(mfs["wax630e_proc_memory_free_bytes"], nil); !ok || v != 400000*1024 {
		t.Errorf("memfree = %v, %v", v, ok)
	}

	// --- netdev VAP ---
	if v, ok := val(mfs["wax630e_proc_interface_tx_bytes"], map[string]string{"interface": "wlan0"}); !ok || v != 333333 {
		t.Errorf("wlan0 tx bytes = %v, %v; want 333333", v, ok)
	}
	if _, ok := val(mfs["wax630e_proc_interface_rx_bytes"], map[string]string{"interface": "lo"}); ok {
		t.Errorf("lo must not have a series")
	}
	if _, ok := val(mfs["wax630e_proc_interface_rx_bytes"], map[string]string{"interface": "ifb5"}); ok {
		t.Errorf("ifb5 (virtual noise) must not have a series")
	}

	// --- thermal ---
	if v, ok := val(mfs["wax630e_thermal_temperature_celsius"], map[string]string{"zone": "cpu-thermal"}); !ok || v != 62.5 {
		t.Errorf("cpu-thermal = %v, %v; want 62.5", v, ok)
	}

	// --- radio (iw dev): 5G on 36/80MHz/23dBm, 2G on 6/20MHz/20dBm ---
	if v, ok := val(mfs["wax630e_radio_channel"], map[string]string{"interface": "wlan0"}); !ok || v != 36 {
		t.Errorf("wlan0 channel = %v, %v; want 36", v, ok)
	}
	if v, ok := val(mfs["wax630e_radio_frequency_mhz"], map[string]string{"interface": "wlan0"}); !ok || v != 5180 {
		t.Errorf("wlan0 freq = %v, %v; want 5180", v, ok)
	}
	if v, ok := val(mfs["wax630e_radio_channel_width_mhz"], map[string]string{"interface": "wlan0"}); !ok || v != 80 {
		t.Errorf("wlan0 width = %v, %v; want 80", v, ok)
	}
	if v, ok := val(mfs["wax630e_radio_txpower_dbm"], map[string]string{"interface": "wlan0"}); !ok || v != 23 {
		t.Errorf("wlan0 txpower = %v, %v; want 23", v, ok)
	}
	if v, ok := val(mfs["wax630e_radio_channel_width_mhz"], map[string]string{"interface": "wlan1"}); !ok || v != 20 {
		t.Errorf("wlan1 width = %v, %v; want 20", v, ok)
	}
	if _, ok := val(mfs["wax630e_radio_info"], map[string]string{"interface": "wlan0", "ssid": "HomeLab-5G", "type": "AP"}); !ok {
		t.Errorf("wlan0 radio_info (HomeLab-5G/AP) not found")
	}

	// --- stations: wlan0 has 2, wlan1 has 0 ---
	if v, ok := val(mfs["wax630e_station_count"], map[string]string{"interface": "wlan0"}); !ok || v != 2 {
		t.Errorf("wlan0 station count = %v, %v; want 2", v, ok)
	}
	if v, ok := val(mfs["wax630e_station_count"], map[string]string{"interface": "wlan1"}); !ok || v != 0 {
		t.Errorf("wlan1 station count = %v, %v; want 0", v, ok)
	}
	if v, ok := val(mfs["wax630e_station_signal_dbm"], map[string]string{"interface": "wlan0", "station": "de:ad:be:ef:00:01"}); !ok || v != -55 {
		t.Errorf("station1 signal = %v, %v; want -55", v, ok)
	}
	if v, ok := val(mfs["wax630e_station_tx_bitrate_mbps"], map[string]string{"interface": "wlan0", "station": "de:ad:be:ef:00:01"}); !ok || v != 866.7 {
		t.Errorf("station1 tx bitrate = %v, %v; want 866.7", v, ok)
	}
	if v, ok := val(mfs["wax630e_station_connected_seconds"], map[string]string{"interface": "wlan0", "station": "de:ad:be:ef:00:02"}); !ok || v != 60 {
		t.Errorf("station2 connected = %v, %v; want 60", v, ok)
	}
	if v, ok := val(mfs["wax630e_station_rx_bytes"], map[string]string{"interface": "wlan0", "station": "de:ad:be:ef:00:01"}); !ok || v != 123456 {
		t.Errorf("station1 rx bytes = %v, %v; want 123456", v, ok)
	}
}
