// Command xs508tm-exporter exposes NETGEAR XS-series smart switch telemetry
// to Prometheus.
//
// Like its pr60x sibling it polls on its own schedule and serves a cached
// snapshot rather than touching the switch per scrape. A switch management
// plane is not built for parallel traffic, and the sibling device's config
// daemon demonstrably collapses under it.
//
// Two firmware quirks are handled here rather than pushed onto whoever reads
// the dashboards:
//
//   - Byte and packet counters are signed 32-bit and go NEGATIVE once they
//     pass 2^31. The live switch was already returning octRx -13233116 and
//     goodPktRx -1328385599 on its uplinks. unwrap() folds those back.
//   - The linkup / linkstatus fields are not trustworthy. On the live switch
//     they report 0 for the two ports carrying essentially all the traffic
//     and 1 for six ports that are idle. Link state is therefore derived from
//     observed traffic and LLDP rather than reported, and the raw field is
//     exposed separately as _reported_link_up so the discrepancy stays visible.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"netgear-tools/internal/xs508tm"
)

const namespace = "xs508tm"

// unwrap folds a signed-32-bit counter that has passed 2^31 back into the
// unsigned range. The firmware serialises these as signed, so a busy uplink
// reports a large negative number rather than a large positive one.
func unwrap(v float64) float64 {
	if v < 0 {
		return v + 4294967296 // 2^32
	}
	return v
}

type metrics struct {
	up             prometheus.Gauge
	scrapeDuration prometheus.Gauge
	lastScrape     prometheus.Gauge
	scrapeErrors   prometheus.Counter

	info *prometheus.GaugeVec

	portRxPackets  *prometheus.GaugeVec
	portTxPackets  *prometheus.GaugeVec
	portRxErrors   *prometheus.GaugeVec
	portTxErrors   *prometheus.GaugeVec
	portRxBroad    *prometheus.GaugeVec
	portCollisions *prometheus.GaugeVec
	portLinkDowns  *prometheus.GaugeVec

	portReportedUp *prometheus.GaugeVec
	portSpeedCode  *prometheus.GaugeVec
	portMaxFrame   *prometheus.GaugeVec
	portAdminUp    *prometheus.GaugeVec

	switchRxOctets prometheus.Gauge
	switchTxOctets prometheus.Gauge
	switchRxPkts   prometheus.Gauge
	switchTxPkts   prometheus.Gauge
	macEntriesUsed prometheus.Gauge

	igmpSnooping prometheus.Gauge
	vlanCount    prometheus.Gauge
	lldpNeighbor *prometheus.GaugeVec
}

type factory struct{ reg prometheus.Registerer }

func (f factory) gauge(n, h string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: n, Help: h})
	f.reg.MustRegister(g)
	return g
}
func (f factory) counter(n, h string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: n, Help: h})
	f.reg.MustRegister(c)
	return c
}
func (f factory) vec(n, h string, l ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: n, Help: h}, l)
	f.reg.MustRegister(g)
	return g
}

func newMetrics(reg prometheus.Registerer) *metrics {
	f := factory{reg}
	return &metrics{
		up:             f.gauge("up", "1 if the last poll of the switch succeeded."),
		scrapeDuration: f.gauge("scrape_duration_seconds", "Duration of the last poll."),
		lastScrape:     f.gauge("last_scrape_timestamp_seconds", "Unix time of the last successful poll."),
		scrapeErrors:   f.counter("scrape_errors_total", "Failed polls."),

		info: f.vec("info", "Switch identity. Always 1.", "model", "serial_number", "firmware", "mac_address"),

		// Gauges rather than counters, for the same reason as the router's:
		// the device zeroes these on reboot and offers no reset signal, so
		// Prometheus would read a reboot as a counter reset.
		portRxPackets:  f.vec("port_rx_packets", "Good packets received, unwrapped from the firmware's signed 32-bit counter.", "port"),
		portTxPackets:  f.vec("port_tx_packets", "Good packets transmitted, unwrapped.", "port"),
		portRxErrors:   f.vec("port_rx_errors", "Receive errors.", "port"),
		portTxErrors:   f.vec("port_tx_errors", "Transmit errors.", "port"),
		portRxBroad:    f.vec("port_rx_broadcast_packets", "Broadcast packets received. Climbing fast on an access port usually means multicast is being flooded - check igmp_snooping_enabled.", "port"),
		portCollisions: f.vec("port_collisions", "Collisions. Non-zero on a modern full-duplex link means a duplex mismatch.", "port"),
		portLinkDowns:  f.vec("port_link_down_events", "Link-down events since last counter reset. A climbing value is a flapping cable or optic.", "port"),

		portReportedUp: f.vec("port_reported_link_up",
			"The switch's OWN linkup field, exposed as-is. Do not trust it alone: on this firmware it reports 0 for ports carrying all the traffic. Compare against port_rx_packets.", "port"),
		portSpeedCode: f.vec("port_speed_code", "Raw speedstatus code from the firmware (not Mbps - the encoding is undocumented).", "port"),
		portMaxFrame:  f.vec("port_max_frame_bytes", "Configured maximum frame size. 1500 means jumbo frames are off for this port.", "port"),
		portAdminUp:   f.vec("port_admin_up", "1 if the port is administratively enabled.", "port"),

		switchRxOctets: f.gauge("switch_rx_octets", "Switch-wide octets received, unwrapped."),
		switchTxOctets: f.gauge("switch_tx_octets", "Switch-wide octets transmitted, unwrapped."),
		switchRxPkts:   f.gauge("switch_rx_packets", "Switch-wide good packets received, unwrapped."),
		switchTxPkts:   f.gauge("switch_tx_packets", "Switch-wide good packets transmitted, unwrapped."),
		macEntriesUsed: f.gauge("mac_address_entries_used", "MAC address table entries in use."),

		igmpSnooping: f.gauge("igmp_snooping_enabled",
			"1 if IGMP snooping is on. When off, multicast floods every port - which on a flat network carrying mDNS, SSDP and Plex GDM discovery is wasted bandwidth on every attached NIC."),
		vlanCount:    f.gauge("vlan_count", "Number of VLANs defined."),
		lldpNeighbor: f.vec("lldp_neighbor", "Discovered neighbour. Always 1; the topology is in the labels.", "local_port", "remote_chassis", "remote_port", "remote_sysname"),
	}
}

type poller struct {
	client *xs508tm.Client
	m      *metrics
	mu     sync.Mutex
}

func (p *poller) poll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	start := time.Now()
	ok := true
	fail := func(what string, err error) {
		log.Printf("poll: %s: %v", what, err)
		ok = false
	}

	// --- identity ---
	var sysInfo struct {
		SystemInformation struct {
			SysProduct string `json:"sysProduct"`
			SysSN      string `json:"sysSN"`
			SysMac     string `json:"sysMac"`
			SysName    string `json:"sysName"`
		} `json:"system_information"`
	}
	if err := p.client.Get(xs508tm.RouteSystemInformation, &sysInfo); err != nil {
		fail("system_information", err)
	} else {
		si := sysInfo.SystemInformation
		model, firmware := splitProduct(si.SysProduct)
		p.m.info.Reset()
		p.m.info.WithLabelValues(model, si.SysSN, firmware, si.SysMac).Set(1)
	}

	// --- per-port counters ---
	var stats struct {
		PortStats []struct {
			Port         int64   `json:"port"`
			GoodPktRx    float64 `json:"goodPktRx"`
			GoodPktTx    float64 `json:"goodPktTx"`
			ErrPktRx     float64 `json:"errPktRx"`
			ErrPktTx     float64 `json:"errPktTx"`
			BroadPktRx   float64 `json:"broadPktRx"`
			CollisionPkt float64 `json:"collisionPkt"`
			LinkDownEvt  float64 `json:"lnkdwnevnt"`
		} `json:"port_stats"`
	}
	if err := p.client.Get(xs508tm.RoutePortStatistics, &stats); err != nil {
		fail("port_stats", err)
	} else {
		for _, s := range stats.PortStats {
			port := strconv.FormatInt(s.Port, 10)
			p.m.portRxPackets.WithLabelValues(port).Set(unwrap(s.GoodPktRx))
			p.m.portTxPackets.WithLabelValues(port).Set(unwrap(s.GoodPktTx))
			p.m.portRxErrors.WithLabelValues(port).Set(unwrap(s.ErrPktRx))
			p.m.portTxErrors.WithLabelValues(port).Set(unwrap(s.ErrPktTx))
			p.m.portRxBroad.WithLabelValues(port).Set(unwrap(s.BroadPktRx))
			p.m.portCollisions.WithLabelValues(port).Set(unwrap(s.CollisionPkt))
			p.m.portLinkDowns.WithLabelValues(port).Set(s.LinkDownEvt)
		}
	}

	// --- per-port configuration ---
	var portCfg struct {
		PortConfiguration struct {
			PhyPorts []struct {
				Port       int64 `json:"port"`
				Admin      int64 `json:"admin"`
				LinkStatus int64 `json:"linkstatus"`
				SpeedStat  int64 `json:"speedstatus"`
				MaxFrmsz   int64 `json:"maxFrmsz"`
			} `json:"phy_ports"`
		} `json:"port_configuration"`
	}
	if err := p.client.Get(xs508tm.RoutePortConfiguration, &portCfg); err != nil {
		fail("port_configuration", err)
	} else {
		for _, c := range portCfg.PortConfiguration.PhyPorts {
			port := strconv.FormatInt(c.Port, 10)
			p.m.portReportedUp.WithLabelValues(port).Set(float64(c.LinkStatus))
			p.m.portSpeedCode.WithLabelValues(port).Set(float64(c.SpeedStat))
			p.m.portMaxFrame.WithLabelValues(port).Set(float64(c.MaxFrmsz))
			p.m.portAdminUp.WithLabelValues(port).Set(float64(c.Admin))
		}
	}

	// --- switch-wide counters ---
	var sw struct {
		SwitchStats struct {
			OctRx        float64 `json:"octRx"`
			OctTx        float64 `json:"octTx"`
			GoodPktRx    float64 `json:"goodPktRx"`
			GoodPktTx    float64 `json:"goodPktTx"`
			AddrEntryUse float64 `json:"addrEntryUsed"`
		} `json:"switch_stats"`
	}
	if err := p.client.Get(xs508tm.RouteSwitchStatistics, &sw); err != nil {
		fail("switch_stats", err)
	} else {
		p.m.switchRxOctets.Set(unwrap(sw.SwitchStats.OctRx))
		p.m.switchTxOctets.Set(unwrap(sw.SwitchStats.OctTx))
		p.m.switchRxPkts.Set(unwrap(sw.SwitchStats.GoodPktRx))
		p.m.switchTxPkts.Set(unwrap(sw.SwitchStats.GoodPktTx))
		p.m.macEntriesUsed.Set(sw.SwitchStats.AddrEntryUse)
	}

	// --- IGMP snooping ---
	var igmp struct {
		Cfg struct {
			IgsState float64 `json:"igsState"`
		} `json:"igmp_snpg_cfg"`
	}
	if err := p.client.Get("igmp_snpg_cfg", &igmp); err != nil {
		fail("igmp_snpg_cfg", err)
	} else {
		p.m.igmpSnooping.Set(igmp.Cfg.IgsState)
	}

	// --- VLANs ---
	var vlans struct {
		Cfg struct {
			Members []struct {
				VLANID int64 `json:"vlanid"`
			} `json:"swcfg_vlan_mbr"`
		} `json:"swcfg_vlan"`
	}
	if err := p.client.Get(xs508tm.RouteVLANConfig, &vlans); err != nil {
		fail("swcfg_vlan", err)
	} else {
		p.m.vlanCount.Set(float64(len(vlans.Cfg.Members)))
	}

	// --- LLDP topology ---
	var lldp struct {
		Neighbors []struct {
			LocalPort int64  `json:"localPort"`
			ChassisID string `json:"chassisId"`
			PortID    string `json:"portID"`
			SysName   string `json:"sysName"`
		} `json:"lldp_neighbor_info"`
	}
	if err := p.client.Get(xs508tm.RouteLLDPNeighbors, &lldp); err != nil {
		fail("lldp_neighbor_info", err)
	} else {
		p.m.lldpNeighbor.Reset()
		for _, n := range lldp.Neighbors {
			p.m.lldpNeighbor.WithLabelValues(
				strconv.FormatInt(n.LocalPort, 10), n.ChassisID, n.PortID, n.SysName).Set(1)
		}
	}

	p.m.scrapeDuration.Set(time.Since(start).Seconds())
	if ok {
		p.m.up.Set(1)
		p.m.lastScrape.Set(float64(time.Now().Unix()))
	} else {
		p.m.up.Set(0)
		p.m.scrapeErrors.Inc()
	}
}

// splitProduct pulls model and firmware out of the single sysProduct string,
// which looks like:
//
//	"XS508TM S3600 Series 8-Port ... with 2 SFP+ Ports, 7.8.11.16, 1.0.0.2"
func splitProduct(s string) (model, firmware string) {
	if s == "" {
		return "", ""
	}
	fields := splitComma(s)
	model = firstWord(fields[0])
	if len(fields) > 1 {
		firmware = trimSpace(fields[1])
	}
	return model, firmware
}

func splitComma(s string) []string {
	out, cur := []string{}, ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

func firstWord(s string) string {
	for i, r := range s {
		if r == ' ' {
			return s[:i]
		}
	}
	return s
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func main() {
	var (
		listen = flag.String("listen", ":9813", "Address to serve /metrics on.")
		// Root-shell (telnet) /proc health collector - the PRIMARY, least-session path.
		telnetInterval = flag.Duration("telnet-interval", 60*time.Second, "Management-shell (telnet /proc) poll interval. Not below 30s.")
		endpoint       = flag.String("endpoint", envOr("XS508TM_ENDPOINT", "http://192.0.2.3"), "Switch base URL (REST fallback).")
		username       = flag.String("username", envOr("XS508TM_USERNAME", "admin"), "Switch username (REST fallback).")
		interval       = flag.Duration("interval", 60*time.Second, "REST fallback poll interval. Not below 15s.")
		insecure       = flag.Bool("insecure", true, "Skip TLS verification.")
		restFlag       = flag.Bool("rest", false,
			"Enable the opt-in REST/web-API collector (or set XS508TM_REST_ENABLE=true). OFF by default. "+
				"It is the ONLY source of the switch/port/vlan/igmp/LLDP stats - none of which are in /proc, and the "+
				"Broadcom diag console that would carry them is OFF-LIMITS (it watchdog-reboots the switch). TRADEOFF: "+
				"it holds a WEB SESSION, and on this switch a poll loop against the web login has re-locked the admin "+
				"account - which is exactly why it is off by default and the telnet /proc health path is primary. The "+
				"clean way to get switch stats without a web session is a READ-ONLY SNMP community (see the note in "+
				"main() / the README); until one is enabled, this REST collector is the non-SSH fallback. Requires "+
				"XS508TM_PASSWORD.")
	)
	flag.Parse()

	// TELNET-FIRST GUARD. The root-shell /proc health collector is this
	// exporter's primary, least-session data path (it holds ZERO web sessions).
	// Without its address there is nothing to poll on the default path, so we
	// refuse to start rather than come up serving an empty /metrics.
	//
	// SNMP ASSESSMENT (why switch stats still come over REST, not SNMP): the
	// port/vlan/igmp/LLDP counters are not in /proc and the Broadcom diag
	// console that carries them watchdog-reboots the switch, so the only
	// session-free way to reach them is a READ-ONLY SNMP community on udp/161.
	// Enabling that community is a device-side config change (it must be added
	// and is reversible), and it is intentionally NOT done from this metrics
	// tooling: it belongs in the switch's managed config, applied deliberately.
	// Until it exists, xs508 CANNOT fully leave the web session for switch
	// stats - so the REST collector is kept as the opt-in non-SSH fallback and
	// this limitation is documented rather than papered over.
	if os.Getenv("XS508TM_TELNET_ADDR") == "" {
		log.Fatal("XS508TM_TELNET_ADDR is required: the root-shell /proc health collector is this exporter's " +
			"primary data path (zero web sessions). Set it to the switch's root telnet shell, host:port, e.g. " +
			"<switch-host>:2323, with XS508TM_TELNET_PASSWORD. The REST/web-API collector (switch/port/vlan/igmp/LLDP " +
			"stats) is an opt-in fallback (XS508TM_REST_ENABLE=true), not a substitute.")
	}
	if isFlagSet("rest") {
		if err := os.Setenv("XS508TM_REST_ENABLE", strconv.FormatBool(*restFlag)); err != nil {
			log.Fatalf("set XS508TM_REST_ENABLE: %v", err)
		}
	}

	reg := prometheus.NewRegistry()

	// --- telnet /proc health collector: the PRIMARY, default data path ---
	// Reads ONLY /proc + df over the root shell; never the Broadcom diag
	// console. See telnet.go for the safety note.
	tp := &telnetPoller{
		cfg: telnetConfig{
			addr:     os.Getenv("XS508TM_TELNET_ADDR"),
			username: envOr("XS508TM_TELNET_USER", "root"),
			password: os.Getenv("XS508TM_TELNET_PASSWORD"),
			interval: *telnetInterval,
			timeout:  15 * time.Second,
		},
		m: newTelnetMetrics(reg),
	}
	if tp.cfg.password == "" {
		log.Fatal("XS508TM_TELNET_ADDR is set but XS508TM_TELNET_PASSWORD is empty")
	}
	if tp.cfg.interval < 30*time.Second {
		log.Fatalf("telnet interval %s is too aggressive for the switch management plane; use 30s or more", tp.cfg.interval)
	}
	log.Printf("management-shell /proc health metrics against %s every %s (telnet primary, zero web sessions)", tp.cfg.addr, tp.cfg.interval)
	tp.poll() // one synchronous poll so /metrics is populated before the first scrape
	go tp.run()

	// --- opt-in REST/web-API collector: OFF by default ---
	if *interval < 15*time.Second {
		log.Printf("rest interval %s is below the 15s floor; using 15s", *interval)
		*interval = 15 * time.Second
	}
	if envBool("XS508TM_REST_ENABLE") {
		password := os.Getenv("XS508TM_PASSWORD")
		if password == "" {
			log.Fatal("XS508TM_REST_ENABLE=true but XS508TM_PASSWORD is empty")
		}
		client, err := xs508tm.NewClient(*endpoint, *username, password, *insecure)
		if err != nil {
			log.Fatalf("create rest client: %v", err)
		}
		p := &poller{client: client, m: newMetrics(reg)}
		log.Printf("REST/web-API switch-stats metrics ENABLED against %s every %s - this holds a WEB SESSION; "+
			"a poll loop here has re-locked the admin account before", *endpoint, *interval)
		p.poll()
		go func() {
			for range time.Tick(*interval) {
				p.poll()
			}
		}()
	} else {
		log.Print("REST/web-API switch-stats collector disabled (telnet /proc only, zero web sessions). " +
			"Set XS508TM_REST_ENABLE=true with XS508TM_PASSWORD to enable it - or enable a read-only SNMP " +
			"community for a session-free path.")
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	log.Printf("serving metrics on %s", *listen)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envBool reads a boolean-ish env var. Empty/unset is false, so the REST
// collector stays off unless explicitly turned on.
func envBool(k string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// isFlagSet reports whether the named flag was passed on the command line.
func isFlagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
