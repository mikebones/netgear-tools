// Web/CGI-admin collector for the MS510TXUP - OPT-IN and OFF BY DEFAULT.
//
// This is the second, config-gated data path. The SSH /proc collector (ssh.go)
// is the DEFAULT and primary source and holds zero web sessions. This collector
// logs into the switch's embedded web server over the get.cgi API to recover
// the metrics that simply are NOT in /proc - per-port LINK up/speed/duplex,
// error/collision counters, STP state, and EEE/green-ethernet - and, while it
// is up, it also re-provides the port config/stats and PoE view as a FALLBACK
// for when the root shell is unreachable.
//
// THE SESSION-TABLE COST (read before enabling). The switch's embedded web
// server has a 4-slot session table shared with the owner's UI and Terraform.
// Enabling this collector consumes ONE slot for the life of the process and
// re-logs in whenever the session expires, so it is deliberately off by default
// and gated behind MS510TXUP_CGI_ENABLE=true. Leave it off unless the CGI-only
// metrics are actually needed; a stuck or duplicated exporter here is exactly
// what fills the table and locks the admin out.
//
// Read-only: only get.cgi commands, never set.cgi. A metrics collector has no
// business mutating a switch.
package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"netgear-tools/internal/ms510txup"
)

// --- device payloads --------------------------------------------------------

// portConfig is one row of get.cgi?cmd=port_port.
type portConfig struct {
	Admin    int    `json:"admin"`
	Link     int    `json:"link"`
	Duplex   int    `json:"duplex"`
	Speed    string `json:"speed"`    // the CONFIGURED setting, usually "Auto"
	PhyStats string `json:"phyStats"` // the NEGOTIATED result, e.g. "1000 Mbps Full Duplex"
	MaxFrame int    `json:"maxFrm"`
	FlowCtrl int    `json:"flowCtrl"`
	MAC      string `json:"mac"`
	IfIndex  int    `json:"ifindex"`
}

type portConfigReply struct {
	Ports []portConfig `json:"ports"`
}

// portStats is one row of get.cgi?cmd=port_portStatistics.
//
// The counters are since the switch's own counter reset, not since boot, and
// the reply carries that age as four separate integers rather than a
// timestamp - hence countTimeDur* below, exported as one seconds gauge so a
// counter reset is visible rather than looking like a traffic cliff.
type portStats struct {
	GoodPktRx     float64 `json:"goodPktRx"`
	ErrPktRx      float64 `json:"errPktRx"`
	BroadPktRx    float64 `json:"broadPktRx"`
	GoodPktTx     float64 `json:"goodPktTx"`
	ErrPktTx      float64 `json:"errPktTx"`
	CollisionPkt  float64 `json:"collisionPkt"`
	LinkDownEvent float64 `json:"linkDownEvent"`
	DurDay        float64 `json:"countTimeDurDay"`
	DurHour       float64 `json:"countTimeDurHour"`
	DurMin        float64 `json:"countTimeDurMin"`
	DurSec        float64 `json:"countTimeDurSec"`
}

type portStatsReply struct {
	Ports []portStats `json:"ports"`
}

// --- metrics ----------------------------------------------------------------

// cgiMetrics are the web-CGI-sourced gauges. They register only when the CGI
// collector is enabled, so the default SSH-only deployment never exposes them.
// The link/STP/EEE families are CGI-only (unavailable over /proc); the port
// config/stats and PoE families overlap the SSH proc_* set and act as fallback.
type cgiMetrics struct {
	up         prometheus.Gauge
	scrapeErrs prometheus.Counter
	scrapeDur  prometheus.Gauge
	lastScrape prometheus.Gauge
	info       *prometheus.GaugeVec
	uptimeDays prometheus.Gauge

	portAdminUp   *prometheus.GaugeVec
	portLinkUp    *prometheus.GaugeVec
	portSpeedMbps *prometheus.GaugeVec
	portFullDup   *prometheus.GaugeVec
	portMaxFrame  *prometheus.GaugeVec
	portFlowCtrl  *prometheus.GaugeVec

	rxGood     *prometheus.GaugeVec
	rxErr      *prometheus.GaugeVec
	rxBroad    *prometheus.GaugeVec
	txGood     *prometheus.GaugeVec
	txErr      *prometheus.GaugeVec
	collisions *prometheus.GaugeVec
	linkDowns  *prometheus.GaugeVec
	counterAge *prometheus.GaugeVec

	igmpGlobal  *prometheus.GaugeVec
	igmpVLAN    *prometheus.GaugeVec
	igmpQuerier *prometheus.GaugeVec

	poePowerW     *prometheus.GaugeVec
	poeCurrentA   *prometheus.GaugeVec
	poeVoltageV   *prometheus.GaugeVec
	poeLimitW     *prometheus.GaugeVec
	poeEnabled    *prometheus.GaugeVec
	poeDelivering *prometheus.GaugeVec
	poeFault      *prometheus.GaugeVec
	poeClass      *prometheus.GaugeVec
	poePriority   *prometheus.GaugeVec
	poeStatusInfo *prometheus.GaugeVec
	poeTotalW     prometheus.Gauge
	poeBudgetW    prometheus.Gauge

	poeNominalW    prometheus.Gauge
	poeConsumedW   prometheus.Gauge
	poeThresholdW  prometheus.Gauge
	poeMgmtMode    prometheus.Gauge
	poeUninterrupt prometheus.Gauge

	eeeGlobal  *prometheus.GaugeVec
	eeePort    *prometheus.GaugeVec
	energyPort *prometheus.GaugeVec

	fwInfo   *prometheus.GaugeVec
	fwStaged prometheus.Gauge

	stpEnabled  prometheus.Gauge
	stpIsRoot   prometheus.Gauge
	stpRootCost prometheus.Gauge
	stpTopoChg  prometheus.Gauge
	stpInfo     *prometheus.GaugeVec
}

func newCGIMetrics(reg prometheus.Registerer) *cgiMetrics {
	f := factory{reg}
	return &cgiMetrics{
		up: f.gauge("up", "1 if the last CGI poll of the switch succeeded. Only present when the CGI "+
			"collector is enabled (MS510TXUP_CGI_ENABLE=true); the SSH availability signal is ms510txup_ssh_up. "+
			"An exporter that cannot log in looks exactly like a quiet network otherwise, which is how a rotated "+
			"password goes unnoticed."),
		scrapeErrs: f.counter("scrape_errors_total", "CGI polls that failed."),
		scrapeDur:  f.gauge("scrape_duration_seconds", "Duration of the last CGI poll."),
		lastScrape: f.gauge("last_scrape_timestamp_seconds", "Unix time of the last successful CGI poll."),
		info:       f.vec("info", "Switch identity. Always 1.", "sysname", "serial", "uptime_days"),
		uptimeDays: f.gauge("uptime_days", "Switch uptime in days, as the device reports it."),

		portAdminUp: f.vec("port_admin_up", "1 if the port is administratively enabled.", "port"),
		portLinkUp: f.vec("port_link_up", "1 if the port has link. CGI-ONLY: not available over /proc, so "+
			"this series exists only while the CGI collector is enabled.", "port"),
		portSpeedMbps: f.vec("port_speed_mbps", "Negotiated link speed in Mbit/s, parsed from phyStats. "+
			"This is the NEGOTIATED result, not the configured setting, which is almost always 'Auto' "+
			"and therefore tells you nothing. CGI-ONLY.", "port"),
		portFullDup:  f.vec("port_full_duplex", "1 if the negotiated link is full duplex. CGI-ONLY.", "port"),
		portMaxFrame: f.vec("port_max_frame_bytes", "Configured maximum frame size.", "port"),
		portFlowCtrl: f.vec("port_flow_control_mode", "802.3x flow control MODE, not a boolean: "+
			"0 disable, 1 symmetric, 2 asymmetric. Named _mode rather than _enabled because the "+
			"device has three states and treating it as on/off is what made the first write silently "+
			"do nothing.", "port"),

		rxGood: f.vec("port_rx_packets", "Good packets received since the counters were last reset. "+
			"CGI-sourced; the SSH proc_port_rx_packets is the primary source when the root shell is up.", "port"),
		rxErr: f.vec("port_rx_errors", "Receive errors since the counters were last reset. CGI-ONLY: the "+
			"/proc portmib sampler carries no error counter.", "port"),
		rxBroad: f.vec("port_rx_broadcast_packets", "Broadcast packets received.", "port"),
		txGood:  f.vec("port_tx_packets", "Good packets transmitted.", "port"),
		txErr:   f.vec("port_tx_errors", "Transmit errors. CGI-ONLY.", "port"),
		collisions: f.vec("port_collisions", "Collisions. Non-zero on a modern full-duplex link means a "+
			"duplex mismatch, not congestion. CGI-ONLY.", "port"),
		linkDowns: f.vec("port_link_down_events", "Times the port has lost link since the counters were "+
			"reset. THE metric to alert on: a port that flaps a dozen times a day is a failing cable or a "+
			"device power-cycling, and it is invisible in throughput graphs.", "port"),
		counterAge: f.vec("port_counter_age_seconds", "How long the port counters have been accumulating. "+
			"Exported because these are NOT since-boot: if this drops, the counters were reset and any "+
			"rate() over the gap is meaningless rather than a traffic cliff.", "port"),

		igmpGlobal: f.vec("igmp_snooping_enabled", "1 if IGMP snooping is enabled globally. When off, the "+
			"switch floods every multicast frame to every port - on a flat LAN carrying mDNS, SSDP and Plex "+
			"discovery that is a constant tax on every attached NIC.", "scope"),
		igmpVLAN: f.vec("igmp_snooping_vlan_enabled", "1 if IGMP snooping is enabled on this VLAN. Enabling "+
			"it globally does NOT enable it per VLAN, and a VLAN left off still floods.", "vlan"),
		igmpQuerier: f.vec("igmp_querier_vlan_enabled", "1 if the switch sends IGMP queries on this VLAN. "+
			"THE THIRD FLAG, and the one that makes the other two mean anything: with no querier nothing "+
			"prompts membership reports, the snooping table never populates, and the switch floods anyway. "+
			"The global querier enable is separate and reading 1 there does NOT mean queries are being "+
			"sent - verified by capture, which saw zero IGMP frames until this was set.", "vlan"),

		// PoE. Ports 1-4 power the four Raspberry Pi 5 cluster nodes, so this
		// is node-availability data, not facilities trivia: a port that stops
		// delivering is a node that hard-powers-off with no shutdown.
		poePowerW: f.vec("poe_port_power_watts", "Power currently delivered on the port, in WATTS. The "+
			"device reports milliwatts as a STRING; this is converted so it can be summed and alerted on "+
			"directly. Ports 1-4 feed the Pi 5 cluster nodes.", "port"),
		poeCurrentA: f.vec("poe_port_current_amps", "Current drawn on the port, in AMPS (device reports "+
			"milliamps).", "port"),
		poeVoltageV: f.vec("poe_port_voltage_volts", "Voltage supplied on the port. A sag here under load "+
			"is the signature of a PoE budget or cable problem rather than a host fault.", "port"),
		poeLimitW: f.vec("poe_port_power_limit_watts", "Configured per-port power ceiling (adminPower), in "+
			"watts. A device drawing close to this is about to be cut off, which presents as an unexplained "+
			"reboot.", "port"),
		poeEnabled: f.vec("poe_port_enabled", "1 if PoE is administratively enabled on the port.", "port"),
		poeDelivering: f.vec("poe_port_delivering", "1 if the port is actually delivering power right now. "+
			"Distinct from enabled: a port can be enabled and searching, which is what an unplugged or dead "+
			"powered device looks like.", "port"),
		poeFault: f.vec("poe_port_fault", "1 if the port reports any fault other than None. The fault text "+
			"itself is a label on poe_port_status_info.", "port"),
		poeClass: f.vec("poe_port_class", "Negotiated 802.3af/at/bt class, as a number. Class 0 is "+
			"unclassified/legacy and caps at 15.4W; classes 4 and above are at/bt.", "port"),
		poePriority: f.vec("poe_port_priority", "Port priority for budget shedding: lower wins. When the "+
			"budget is exceeded the switch cuts the LOWEST priority ports first, so leaving the cluster "+
			"nodes at the same priority as everything else means the shedding order is arbitrary.", "port"),
		poeStatusInfo: f.vec("poe_port_status_info", "Always 1. Carries the human-readable status, fault "+
			"and class as labels, so a dashboard can show 'Searching' or a fault name without a lookup "+
			"table in the query.", "port", "status", "fault", "class"),
		poeTotalW: f.gauge("poe_total_power_watts", "Sum of power delivered across all PoE ports. Compare "+
			"against poe_budget_watts for headroom."),
		poeBudgetW: f.gauge("poe_port_admin_power_max_watts", "The per-port power CEILING, not a budget. "+
			"Renamed from poe_budget_watts, which was wrong: this is poe_port's adminPower_max and says "+
			"nothing about chassis headroom. The real budget is poe_nominal_power_watts."),

		poeNominalW: f.gauge("poe_nominal_power_watts", "The chassis PoE budget in watts - what the power "+
			"supply can actually deliver across all ports. From poe_conf; poe_port does not carry it."),
		poeConsumedW: f.gauge("poe_consumed_power_watts", "Total PoE draw as the switch itself measures it. "+
			"Compare against poe_nominal_power_watts for true headroom."),
		poeThresholdW: f.gauge("poe_threshold_power_watts", "Draw at which the switch starts shedding ports, "+
			"lowest priority first. Crossing this is the event that makes per-port priority matter."),
		poeMgmtMode: f.gauge("poe_power_management_mode", "1 static, 2 dynamic. Static reserves each port's "+
			"full class allocation whether or not the device draws it; dynamic budgets against measured "+
			"draw, so it fits more devices in the same envelope."),
		poeUninterrupt: f.gauge("poe_uninterrupted_enabled", "1 if PoE is held up across a switch reboot. "+
			"THIS IS WHY A FIRMWARE UPDATE DOES NOT COLD-BOOT THE CLUSTER - all four Pi nodes are powered "+
			"by this switch, so a 0 here turns any switch restart into a simultaneous hard power cut."),

		eeeGlobal: f.vec("green_ethernet_enabled", "1 if the setting is on globally. `eee` is 802.3az "+
			"energy-efficient Ethernet, `energy` is auto power down. Both are OFF here deliberately: EEE's "+
			"wake latency shows up as jitter and, on unlucky PHY pairings, link flaps - and the four Pis "+
			"and the AP all hang off this switch. Exported to catch a firmware upgrade turning it on. "+
			"CGI-ONLY: green-ethernet state is not in /proc.", "setting"),
		eeePort: f.vec("green_ethernet_eee_port_enabled", "1 if 802.3az EEE is on for this port. CGI-ONLY.", "port"),
		energyPort: f.vec("green_ethernet_auto_power_down_port_enabled", "1 if auto power down is on for "+
			"this port - it idles a port that has no link. CGI-ONLY.", "port"),

		fwInfo: f.vec("firmware_info", "Always 1. Carries both image slots and which one is running vs "+
			"which boots next. The switch keeps TWO images, so 'the firmware version' is two answers.",
			"active", "next_active", "image1", "image2"),
		stpEnabled: f.gauge("stp_enabled", "1 if spanning tree is running. With a single path between "+
			"switches STP does nothing day to day, which is exactly why it goes unnoticed if it stops - "+
			"and an accidental loop on a flat LAN carrying the cluster is not a recoverable afternoon. "+
			"CGI-ONLY: STP state is not in /proc."),
		stpIsRoot: f.gauge("stp_is_root_bridge", "1 if THIS switch is the spanning-tree root. Normally 0 "+
			"here: the 10G XS508TM is root, which is the sensible topology. This flipping means the root "+
			"election changed, i.e. the other switch went away. CGI-ONLY."),
		stpRootCost: f.gauge("stp_root_path_cost", "Path cost from this switch to the root bridge. A "+
			"change means the path to root changed - a link died or a new one appeared. CGI-ONLY."),
		stpTopoChg: f.gauge("stp_topology_changes_total", "Spanning-tree topology changes since boot. "+
			"THE INSTABILITY SIGNAL: each one means a link somewhere in the L2 domain went away or came "+
			"back, and each briefly disrupts forwarding. Catches flaps on the OTHER switch too, which "+
			"per-port link-down counters here cannot see. Resets to 0 on reboot, so use increase(). CGI-ONLY."),
		stpInfo: f.vec("stp_info", "Always 1. Carries the STP mode and the bridge IDs as labels. CGI-ONLY.",
			"mode", "bridge_id", "root_bridge_id"),

		fwStaged: f.gauge("firmware_staged", "1 when the next-active image differs from the running one - "+
			"an upgrade has been FLASHED AND IS WAITING FOR A REBOOT. "+
			"This is the metric worth alerting on. A staged switch is armed: any restart, including an "+
			"unplanned one, boots the new firmware unsupervised. On this switch that reboot takes all five "+
			"cluster nodes off the network at once, so it should happen in a window someone chose."),
	}
}

// --- parsing ----------------------------------------------------------------

// Matches "1000 Mbps" and "2.5 Gbps" alike. THE DECIMAL IS NOT OPTIONAL to
// handle: with a bare (\d+) the regex scans forward and matches the "5" out of
// "2.5 Gbps", reporting a 2.5G link as 5000 Mbit/s. That is exactly what this
// exporter did until the switch's own UI was compared against it.
var speedRe = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*([MG])bps`)

// parsePhyStats turns "1000 Mbps Full Duplex" into 1000 and true.
//
// The `speed` field is deliberately NOT used for this: it holds the configured
// setting, which is "Auto" on every port here, so reading it would report the
// same value for a 1 Gbit link and a 100 Mbit one.
func parsePhyStats(s string) (mbps float64, full bool, ok bool) {
	m := speedRe.FindStringSubmatch(s)
	if m == nil {
		return 0, false, false
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false, false
	}
	if m[2] == "G" {
		n *= 1000
	}
	return n, strings.Contains(strings.ToLower(s), "full"), true
}

// --- poller -----------------------------------------------------------------

// cgiPoller owns the web-CGI-side collection. Like the SSH poller it runs on
// its own timer and serves cached gauges rather than dialing per scrape, so it
// holds a single web session rather than opening one per Prometheus scrape.
type cgiPoller struct {
	c  *ms510txup.Client
	m  *cgiMetrics
	mu sync.Mutex
}

func (p *cgiPoller) run(interval time.Duration) {
	for range time.Tick(interval) {
		p.poll()
	}
}

func (p *cgiPoller) poll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	start := time.Now()

	var failed bool
	fail := func(what string, err error) {
		log.Printf("cgi poll: %s: %v", what, err)
		failed = true
	}

	if si, err := p.c.GetSysInfo(); err != nil {
		fail("GetSysInfo", err)
	} else {
		p.m.info.Reset()
		p.m.info.WithLabelValues(si.SysName, si.SysSN, strconv.Itoa(si.UpTimeDays)).Set(1)
		p.m.uptimeDays.Set(float64(si.UpTimeDays))
	}

	var cfg portConfigReply
	if err := p.c.Get("port_port", &cfg); err != nil {
		fail("port_port", err)
	} else {
		p.m.portAdminUp.Reset()
		p.m.portLinkUp.Reset()
		p.m.portSpeedMbps.Reset()
		p.m.portFullDup.Reset()
		p.m.portMaxFrame.Reset()
		p.m.portFlowCtrl.Reset()
		for i, pc := range cfg.Ports {
			// ifindex is authoritative; fall back to position for a firmware
			// that omits it rather than mislabelling every port silently.
			idx := pc.IfIndex
			if idx == 0 {
				idx = i + 1
			}
			port := strconv.Itoa(idx)
			p.m.portAdminUp.WithLabelValues(port).Set(b2f(pc.Admin == 1))
			p.m.portLinkUp.WithLabelValues(port).Set(b2f(pc.Link == 1))
			p.m.portMaxFrame.WithLabelValues(port).Set(float64(pc.MaxFrame))
			// MODE, not a boolean: 0 disable, 1 symmetric, 2 asymmetric.
			p.m.portFlowCtrl.WithLabelValues(port).Set(float64(pc.FlowCtrl))
			if mbps, full, ok := parsePhyStats(pc.PhyStats); ok {
				p.m.portSpeedMbps.WithLabelValues(port).Set(mbps)
				p.m.portFullDup.WithLabelValues(port).Set(b2f(full))
			} else {
				// No link: report 0 rather than leaving the previous value,
				// which would otherwise persist and look like a live link.
				p.m.portSpeedMbps.WithLabelValues(port).Set(0)
				p.m.portFullDup.WithLabelValues(port).Set(0)
			}
		}
	}

	var st portStatsReply
	if err := p.c.Get("port_portStatistics", &st); err != nil {
		fail("port_portStatistics", err)
	} else {
		p.m.rxGood.Reset()
		p.m.rxErr.Reset()
		p.m.rxBroad.Reset()
		p.m.txGood.Reset()
		p.m.txErr.Reset()
		p.m.collisions.Reset()
		p.m.linkDowns.Reset()
		p.m.counterAge.Reset()
		for i, ps := range st.Ports {
			// port_portStatistics carries no ifindex, so position is all there
			// is. It is in the same order as port_port on this firmware.
			port := strconv.Itoa(i + 1)
			p.m.rxGood.WithLabelValues(port).Set(ps.GoodPktRx)
			p.m.rxErr.WithLabelValues(port).Set(ps.ErrPktRx)
			p.m.rxBroad.WithLabelValues(port).Set(ps.BroadPktRx)
			p.m.txGood.WithLabelValues(port).Set(ps.GoodPktTx)
			p.m.txErr.WithLabelValues(port).Set(ps.ErrPktTx)
			p.m.collisions.WithLabelValues(port).Set(ps.CollisionPkt)
			p.m.linkDowns.WithLabelValues(port).Set(ps.LinkDownEvent)
			p.m.counterAge.WithLabelValues(port).Set(
				ps.DurDay*86400 + ps.DurHour*3600 + ps.DurMin*60 + ps.DurSec)
		}
	}

	if g, err := p.c.GetIGMPSnooping(); err != nil {
		fail("GetIGMPSnooping", err)
	} else {
		p.m.igmpGlobal.WithLabelValues("global").Set(b2f(g.State == 1))
	}
	if vs, err := p.c.ListIGMPSnoopingVLANs(); err != nil {
		fail("ListIGMPSnoopingVLANs", err)
	} else {
		p.m.igmpVLAN.Reset()
		for _, v := range vs {
			p.m.igmpVLAN.WithLabelValues(strconv.Itoa(v.VLANID)).Set(b2f(v.State == 1))
		}
	}

	if en, all, err := p.c.ListIGMPQuerierVLANs(); err != nil {
		fail("ListIGMPQuerierVLANs", err)
	} else {
		on := map[int]bool{}
		for _, v := range en {
			on[v] = true
		}
		p.m.igmpQuerier.Reset()
		// Every VLAN the switch knows, not just the enabled ones - a VLAN
		// that silently drops off the querier list has to show as 0 rather
		// than vanish, or the graph looks unchanged.
		for _, v := range all {
			p.m.igmpQuerier.WithLabelValues(strconv.Itoa(v)).Set(b2f(on[v]))
		}
	}

	if poe, err := p.c.GetPoE(); err != nil {
		fail("GetPoE", err)
	} else {
		p.m.poePowerW.Reset()
		p.m.poeCurrentA.Reset()
		p.m.poeVoltageV.Reset()
		p.m.poeLimitW.Reset()
		p.m.poeEnabled.Reset()
		p.m.poeDelivering.Reset()
		p.m.poeFault.Reset()
		p.m.poeClass.Reset()
		p.m.poePriority.Reset()
		p.m.poeStatusInfo.Reset()
		totalMW := 0
		for i, pp := range poe.Ports {
			// Only the PoE-capable ports appear here, in front-panel order,
			// so index+1 is the port number. The two 10G uplinks are absent
			// because they deliver no power.
			port := strconv.Itoa(i + 1)
			mw := ms510txup.PoEMilliwatts(pp.Power)
			totalMW += mw
			status := ms510txup.PoELangValue(pp.Status)
			fault := ms510txup.PoELangValue(pp.Fault)
			class := ms510txup.PoELangValue(pp.Class)

			p.m.poePowerW.WithLabelValues(port).Set(float64(mw) / 1000)
			p.m.poeCurrentA.WithLabelValues(port).Set(float64(pp.Amphere) / 1000)
			p.m.poeVoltageV.WithLabelValues(port).Set(float64(pp.Voltage))
			p.m.poeLimitW.WithLabelValues(port).Set(float64(ms510txup.PoEMilliwatts(pp.AdminPower)) / 1000)
			p.m.poeEnabled.WithLabelValues(port).Set(b2f(pp.State == 1))
			p.m.poeDelivering.WithLabelValues(port).Set(b2f(strings.EqualFold(status, "Delivering")))
			// "None" is the no-fault value; anything else, including a value
			// this firmware version invents, counts as a fault.
			p.m.poeFault.WithLabelValues(port).Set(b2f(!strings.EqualFold(fault, "None") && fault != ""))
			if n, err := strconv.Atoi(class); err == nil {
				p.m.poeClass.WithLabelValues(port).Set(float64(n))
			}
			p.m.poePriority.WithLabelValues(port).Set(float64(pp.Priority))
			p.m.poeStatusInfo.WithLabelValues(port, status, fault, class).Set(1)
		}
		p.m.poeTotalW.Set(float64(totalMW) / 1000)
		p.m.poeBudgetW.Set(float64(poe.AdminPowerMax) / 1000)
	}

	if b, unintr, err := p.c.GetPoEBudget(); err != nil {
		fail("GetPoEBudget", err)
	} else {
		// Watt figures arrive as decimal STRINGS.
		setW := func(g prometheus.Gauge, s string) {
			if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
				g.Set(v)
			}
		}
		setW(p.m.poeNominalW, b.Nominal)
		setW(p.m.poeConsumedW, b.Consumed)
		setW(p.m.poeThresholdW, b.ThresholdPower)
		p.m.poeMgmtMode.Set(float64(b.PowerMgmtMode))
		p.m.poeUninterrupt.Set(b2f(unintr))
	}

	if stp, err := p.c.GetSTP(); err != nil {
		fail("GetSTP", err)
	} else {
		p.m.stpEnabled.Set(b2f(stp.State))
		p.m.stpIsRoot.Set(b2f(stp.IsRoot()))
		p.m.stpRootCost.Set(float64(stp.DesignatedRootCost))
		p.m.stpTopoChg.Set(float64(stp.TopologyChanges))
		p.m.stpInfo.Reset()
		p.m.stpInfo.WithLabelValues(stp.OperMode, stp.BridgeID, stp.DesignatedRootBridgeID).Set(1)
	}

	if fw, err := p.c.GetFirmware(); err != nil {
		fail("GetFirmware", err)
	} else {
		p.m.fwInfo.Reset()
		p.m.fwInfo.WithLabelValues(fw.ActiveVersion(), fw.NextActiveVersion(), fw.Image1, fw.Image2).Set(1)
		p.m.fwStaged.Set(b2f(fw.Staged()))
	}

	if g, err := p.c.GetGreenEthernet(); err != nil {
		fail("GetGreenEthernet", err)
	} else {
		p.m.eeeGlobal.WithLabelValues("eee").Set(b2f(g.EEE == 1))
		p.m.eeeGlobal.WithLabelValues("energy").Set(b2f(g.Energy == 1))
	}
	if ports, err := p.c.ListGreenEthernetPorts(); err != nil {
		fail("ListGreenEthernetPorts", err)
	} else {
		p.m.eeePort.Reset()
		p.m.energyPort.Reset()
		for i, g := range ports {
			// These rows carry no port number; position is the only id.
			port := strconv.Itoa(i + 1)
			p.m.eeePort.WithLabelValues(port).Set(b2f(g.EEE == 1))
			p.m.energyPort.WithLabelValues(port).Set(b2f(g.Energy == 1))
		}
	}

	p.m.scrapeDur.Set(time.Since(start).Seconds())
	if failed {
		p.m.scrapeErrs.Inc()
		p.m.up.Set(0)
		return
	}
	p.m.up.Set(1)
	p.m.lastScrape.Set(float64(time.Now().Unix()))
}

// cgiConfig is the opt-in CGI collector's configuration, drawn from the
// environment only when it is enabled.
type cgiConfig struct {
	endpoint string
	password string
	insecure bool
	interval time.Duration
}

// loadCGIConfig returns (nil, nil) when the CGI collector is disabled - which is
// the DEFAULT: it is opt-in behind MS510TXUP_CGI_ENABLE=true. When enabled it
// requires MS510TXUP_ENDPOINT and MS510TXUP_PASSWORD. Enabling it consumes one
// of the switch's four web session slots for the life of the process; keep it
// off unless the CGI-only metrics (link/STP/EEE) are actually needed.
func loadCGIConfig(interval time.Duration) (*cgiConfig, error) {
	if !envBool("MS510TXUP_CGI_ENABLE") {
		return nil, nil
	}
	endpoint := os.Getenv("MS510TXUP_ENDPOINT")
	if endpoint == "" {
		return nil, fmt.Errorf("MS510TXUP_CGI_ENABLE=true but MS510TXUP_ENDPOINT is empty: " +
			"set it to the switch base URL, e.g. https://<switch-host>")
	}
	password := os.Getenv("MS510TXUP_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("MS510TXUP_CGI_ENABLE=true but MS510TXUP_PASSWORD is empty")
	}
	return &cgiConfig{
		endpoint: endpoint,
		password: password,
		insecure: true,
		interval: interval,
	}, nil
}

// envBool reads a boolean-ish env var. Empty/unset is false, so the CGI
// collector stays off unless explicitly turned on.
func envBool(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
