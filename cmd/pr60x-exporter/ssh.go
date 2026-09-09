// Root-SSH telemetry for the PR60X - this exporter's PRIMARY and default data
// path. It reads the OpenWrt userland over the device's dropbear root shell
// (key auth, no password) with a single session per interval: ubus for WAN
// state, /proc for interfaces/conntrack/CPU/memory/uptime, /sys for thermals,
// lsmod for the Qualcomm NSS/PPE offload engine, and `tc -s qdisc` for the
// CAKE/sqm shaper.
//
// WHY SSH IS THE DEFAULT, NOT THE JSON-RPC API
// --------------------------------------------
// The web-admin JSON-RPC path (client.go / the REST collector in main.go) has
// two problems this one does not. First, its backend config daemon degrades
// under rapid or concurrent RPC load and wedges into
// "Failed to call process_configd_request" for everything until it recovers -
// the whole reason the REST poll runs on a slow timer. Second, it authenticates
// with the router's ADMIN password, the single credential that owns the network
// edge, which is being rotated out of band; reading over an SSH KEY instead
// removes the exporter's dependence on that password entirely. So SSH is the
// default and REST is an opt-in fallback (PR60X_REST_ENABLE), mirroring the
// ms510txup exporter's SSH-primary + web-fallback idiom.
//
// WHAT SSH EXPOSES that the least-session path should own:
//   - /proc/net/dev      - per-interface rx/tx bytes, packets, errors, drops.
//     The WAN and LAN throughput/error counters.
//   - ubus network.interface.wan status - WAN up flag and carrier uptime, from
//     the same daemon the UI reads, without a web session.
//   - nf_conntrack_count/max - firewall connection-tracking occupancy.
//   - /proc/loadavg, /proc/meminfo, /proc/uptime - management-CPU health.
//   - /sys/class/thermal - SoC thermal zones (real die temperatures, unlike the
//     single chassis figure the API returns).
//   - lsmod              - whether the qca-nss-ecm / ppe flow-offload modules
//     are loaded. This is the CAKE story: hardware flow
//     offload BYPASSES the qdisc, so CAKE only actually
//     shapes when ecm is unloaded - so the offload module
//     state and the qdisc stats belong together.
//   - tc -s qdisc show   - CAKE/sqm qdisc counters per interface (sent, dropped,
//     overlimits, backlog) - proof the shaper is live and
//     how hard it is working.
//
// WHAT STAYS REST-ONLY (not available, or not cleanly, over this shell), and so
// lives in the opt-in REST collector: negotiated per-port link up/speed (a
// switch-register read, not a netdev), the chassis fan RPM and the single API
// temperature sensor, and the security-posture flags (UPnP/DMZ/WAN-ping/secure-
// DNS/port-forwards) which are config the JSON-RPC API models directly. These
// are the router equivalents of the ms510's CGI-only link/STP/EEE metrics.
//
// SAFETY - READ-ONLY. Every command in the batch is a passive read (cat/ubus
// call ... status/lsmod/tc -s show). Nothing here writes a uci value, calls a
// mutating ubus method, or reconfigures a qdisc. A metrics collector has no
// business changing the router; keep it that way.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/prometheus/client_golang/prometheus"
)

// sshConfig is the connection detail, all from the environment so nothing
// device-specific is baked into a public repository.
type sshConfig struct {
	addr     string // host:port, e.g. router.lan:22
	user     string
	keyPEM   []byte
	hostKey  ssh.PublicKey // nil => accept any (LAN device)
	interval time.Duration
	timeout  time.Duration
}

// sshMetrics are the root-SSH gauges - the exporter's default metric set. The
// proc_/ubus_/nss_/qdisc_ name segments are honest source markers and keep the
// families distinct from the REST fallback's overlapping ones.
type sshMetrics struct {
	up            prometheus.Gauge
	scrapeSeconds prometheus.Gauge
	scrapeErrors  prometheus.Counter

	uptimeSeconds prometheus.Gauge
	load1         prometheus.Gauge
	load5         prometheus.Gauge
	load15        prometheus.Gauge

	memTotal     prometheus.Gauge
	memFree      prometheus.Gauge
	memAvailable prometheus.Gauge
	memCached    prometheus.Gauge

	ifRxBytes   *prometheus.GaugeVec
	ifTxBytes   *prometheus.GaugeVec
	ifRxPackets *prometheus.GaugeVec
	ifTxPackets *prometheus.GaugeVec
	ifRxErrors  *prometheus.GaugeVec
	ifTxErrors  *prometheus.GaugeVec
	ifRxDrops   *prometheus.GaugeVec
	ifTxDrops   *prometheus.GaugeVec

	conntrackCount prometheus.Gauge
	conntrackMax   prometheus.Gauge

	thermalC *prometheus.GaugeVec

	nssModule *prometheus.GaugeVec

	qdiscInfo      *prometheus.GaugeVec
	qdiscSentBytes *prometheus.GaugeVec
	qdiscSentPkts  *prometheus.GaugeVec
	qdiscDropped   *prometheus.GaugeVec
	qdiscOverlimit *prometheus.GaugeVec
	qdiscBacklogB  *prometheus.GaugeVec
	qdiscBacklogP  *prometheus.GaugeVec

	wanUp     prometheus.Gauge
	wanUptime prometheus.Gauge
}

func newSSHMetrics(reg prometheus.Registerer) *sshMetrics {
	f := factory{reg}
	return &sshMetrics{
		up: f.gauge("ssh_up", "1 if the last root-SSH poll of the router succeeded. 0 means the dropbear "+
			"root shell was unreachable (or the key was rejected) - and since SSH is this exporter's primary "+
			"path, a 0 means no fresh metrics unless the opt-in REST collector is also enabled. THE availability "+
			"signal to alert on."),
		scrapeSeconds: f.gauge("ssh_scrape_duration_seconds", "Duration of the last root-SSH poll."),
		scrapeErrors:  f.counter("ssh_scrape_errors_total", "Failed root-SSH polls."),

		uptimeSeconds: f.gauge("proc_uptime_seconds", "Seconds since boot from /proc/uptime. A reset means the router rebooted."),
		load1:         f.gauge("proc_load1", "1-minute load average of the management CPU."),
		load5:         f.gauge("proc_load5", "5-minute load average of the management CPU."),
		load15:        f.gauge("proc_load15", "15-minute load average of the management CPU."),

		memTotal:     f.gauge("proc_memory_total_bytes", "MemTotal from /proc/meminfo."),
		memFree:      f.gauge("proc_memory_free_bytes", "MemFree from /proc/meminfo."),
		memAvailable: f.gauge("proc_memory_available_bytes", "MemAvailable from /proc/meminfo - the honest 'how much can actually be used' figure. A steady decline is a management-plane leak."),
		memCached:    f.gauge("proc_memory_cached_bytes", "Cached memory from /proc/meminfo."),

		ifRxBytes: f.gaugeVec("proc_interface_rx_bytes", "Bytes received on the netdev, from /proc/net/dev. Since-boot counter; "+
			"use rate()/increase() and guard with proc_uptime_seconds against reboots.", "interface"),
		ifTxBytes:   f.gaugeVec("proc_interface_tx_bytes", "Bytes transmitted on the netdev, from /proc/net/dev.", "interface"),
		ifRxPackets: f.gaugeVec("proc_interface_rx_packets", "Packets received on the netdev, from /proc/net/dev.", "interface"),
		ifTxPackets: f.gaugeVec("proc_interface_tx_packets", "Packets transmitted on the netdev, from /proc/net/dev.", "interface"),
		ifRxErrors:  f.gaugeVec("proc_interface_rx_errors", "Receive errors on the netdev.", "interface"),
		ifTxErrors:  f.gaugeVec("proc_interface_tx_errors", "Transmit errors on the netdev.", "interface"),
		ifRxDrops:   f.gaugeVec("proc_interface_rx_drops", "Receive drops on the netdev.", "interface"),
		ifTxDrops:   f.gaugeVec("proc_interface_tx_drops", "Transmit drops on the netdev.", "interface"),

		conntrackCount: f.gauge("conntrack_count", "Connections currently in the netfilter conntrack table (nf_conntrack_count). "+
			"Compare against conntrack_max - exhausting the table drops new connections while established ones survive, a confusing failure."),
		conntrackMax: f.gauge("conntrack_max", "Conntrack table size (nf_conntrack_max)."),

		thermalC: f.gaugeVec("thermal_temperature_celsius", "SoC thermal-zone temperature in degrees C, from /sys/class/thermal. "+
			"Real die temperatures, one series per zone type - distinct from the single system_temperature_celsius the API returns.", "zone"),

		nssModule: f.gaugeVec("nss_module_loaded", "1 if the named Qualcomm NSS/PPE kernel module is loaded (from lsmod). "+
			"THIS IS THE CAKE STORY: hardware flow offload (qca_nss_ecm and friends) BYPASSES the qdisc, so CAKE only shapes "+
			"when ecm is unloaded. A 1 for qca_nss_ecm alongside a live cake qdisc means the shaper is being bypassed.", "module"),

		qdiscInfo:      f.gaugeVec("qdisc_info", "Always 1. The qdisc attached to the interface; the kind (e.g. cake, fq_codel, noqueue) is a label.", "interface", "kind"),
		qdiscSentBytes: f.gaugeVec("qdisc_sent_bytes", "Bytes sent through the qdisc on the interface (tc -s qdisc). Since attach; use rate().", "interface"),
		qdiscSentPkts:  f.gaugeVec("qdisc_sent_packets", "Packets sent through the qdisc on the interface.", "interface"),
		qdiscDropped:   f.gaugeVec("qdisc_dropped_packets", "Packets DROPPED by the qdisc - for CAKE this is the bufferbloat control actually working; a rising rate under load is expected and healthy.", "interface"),
		qdiscOverlimit: f.gaugeVec("qdisc_overlimits", "Qdisc overlimit events - packets delayed because the shaped rate was reached. The signal that the CAKE bandwidth ceiling is biting.", "interface"),
		qdiscBacklogB:  f.gaugeVec("qdisc_backlog_bytes", "Bytes currently queued in the qdisc backlog on the interface.", "interface"),
		qdiscBacklogP:  f.gaugeVec("qdisc_backlog_packets", "Packets currently queued in the qdisc backlog on the interface.", "interface"),

		wanUp:     f.gauge("wan_up", "1 if ubus reports the WAN interface up (network.interface.wan status). Read from the same daemon the UI uses, over SSH, with no web session."),
		wanUptime: f.gauge("wan_uptime_seconds", "Seconds the WAN interface has been up per ubus. A reset without a router reboot (proc_uptime_seconds steady) is a WAN carrier flap - a reconnect on the ISP side."),
	}
}

// sshPoller owns the root-SSH collection. Like the REST poller it runs on its
// own timer and serves cached gauges rather than dialing per scrape.
type sshPoller struct {
	cfg sshConfig
	m   *sshMetrics
	mu  sync.Mutex
}

func (p *sshPoller) run() {
	p.poll()
	for range time.Tick(p.cfg.interval) {
		p.poll()
	}
}

// poll opens exactly ONE SSH session, runs the fixed read-only batch, parses it
// and updates the gauges. One session per interval keeps the load off the
// router's small management plane.
func (p *sshPoller) poll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	start := time.Now()
	out, err := p.collect()
	p.m.scrapeSeconds.Set(time.Since(start).Seconds())
	if err != nil {
		log.Printf("ssh poll: %v", err)
		p.m.up.Set(0)
		p.m.scrapeErrors.Inc()
		return
	}
	sec := splitSSHSections(out)
	p.parseUptime(sec["UPTIME"])
	p.parseLoadavg(sec["LOADAVG"])
	p.parseMeminfo(sec["MEMINFO"])
	p.parseNetdev(sec["NETDEV"])
	p.parseConntrack(sec["CTCOUNT"], sec["CTMAX"])
	p.parseThermal(sec["THERMAL"])
	p.parseLsmod(sec["LSMOD"])
	p.parseQdisc(sec["QDISC"])
	p.parseWAN(sec["WAN"])
	p.m.up.Set(1)
}

// nssModules is the fixed set of Qualcomm offload modules whose load state is
// reported. Listing them explicitly (rather than dumping all of lsmod) keeps
// the metric cardinality bounded and the intent obvious: these are the modules
// whose presence bypasses the CAKE qdisc.
var nssModules = []string{"qca_nss_ecm", "qca_nss_drv", "qca_nss_ppe", "ecm"}

// sshBatch is the ENTIRE set of commands this collector will ever run. Every
// line is a passive read - see the safety note at the top of the file before
// adding to it. conntrack_count/max are read from both the netfilter and the
// legacy sysctl path so a kernel that only has one still reports.
var sshBatch = buildSSHBatch()

func buildSSHBatch() string {
	var b strings.Builder
	b.WriteString(`echo @@UPTIME; cat /proc/uptime 2>/dev/null; `)
	b.WriteString(`echo @@LOADAVG; cat /proc/loadavg 2>/dev/null; `)
	b.WriteString(`echo @@MEMINFO; cat /proc/meminfo 2>/dev/null; `)
	b.WriteString(`echo @@NETDEV; cat /proc/net/dev 2>/dev/null; `)
	b.WriteString(`echo @@CTCOUNT; cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null; `)
	b.WriteString(`echo @@CTMAX; cat /proc/sys/net/netfilter/nf_conntrack_max /proc/sys/net/nf_conntrack_max 2>/dev/null; `)
	b.WriteString(`echo @@THERMAL; for z in /sys/class/thermal/thermal_zone*; do [ -r "$z/temp" ] && echo "$(cat $z/type 2>/dev/null) $(cat $z/temp 2>/dev/null)"; done 2>/dev/null; `)
	b.WriteString(`echo @@LSMOD; lsmod 2>/dev/null; `)
	b.WriteString(`echo @@QDISC; tc -s qdisc show 2>/dev/null; `)
	b.WriteString(`echo @@WAN; ubus call network.interface.wan status 2>/dev/null; `)
	b.WriteString(`echo @@DONE`)
	return b.String()
}

// collect dials, authenticates and runs the batch over a single session.
func (p *sshPoller) collect() (string, error) {
	signer, err := ssh.ParsePrivateKey(p.cfg.keyPEM)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	cb := ssh.InsecureIgnoreHostKey() //nolint:gosec // LAN appliance; pinned when a host key is supplied.
	if p.cfg.hostKey != nil {
		cb = ssh.FixedHostKey(p.cfg.hostKey)
	}
	cfg := &ssh.ClientConfig{
		User:            p.cfg.user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: cb,
		Timeout:         p.cfg.timeout,
	}
	client, err := ssh.Dial("tcp", p.cfg.addr, cfg)
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", p.cfg.addr, err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()

	out, err := sess.Output(sshBatch)
	if err != nil {
		return "", fmt.Errorf("running /proc batch: %w", err)
	}
	return string(out), nil
}

// splitSSHSections carves the batch output on the @@NAME markers it emits.
func splitSSHSections(out string) map[string]string {
	sections := map[string]string{}
	var cur string
	var b strings.Builder
	flush := func() {
		if cur != "" {
			sections[cur] = b.String()
		}
		b.Reset()
	}
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimRight(line, "\r")
		if strings.HasPrefix(t, "@@") {
			flush()
			cur = strings.TrimSpace(strings.TrimPrefix(t, "@@"))
			continue
		}
		b.WriteString(t)
		b.WriteByte('\n')
	}
	flush()
	return sections
}

// --- /proc/uptime, /proc/loadavg, /proc/meminfo -----------------------------

func (p *sshPoller) parseUptime(s string) {
	if v, ok := firstFloat(s); ok {
		p.m.uptimeSeconds.Set(v)
	}
}

func (p *sshPoller) parseLoadavg(s string) {
	fields := strings.Fields(s)
	if len(fields) < 3 {
		return
	}
	if v, err := strconv.ParseFloat(fields[0], 64); err == nil {
		p.m.load1.Set(v)
	}
	if v, err := strconv.ParseFloat(fields[1], 64); err == nil {
		p.m.load5.Set(v)
	}
	if v, err := strconv.ParseFloat(fields[2], 64); err == nil {
		p.m.load15.Set(v)
	}
}

func (p *sshPoller) parseMeminfo(s string) {
	mem := parseKV(s) // values in kB
	setKB(mem, "MemTotal", p.m.memTotal)
	setKB(mem, "MemFree", p.m.memFree)
	setKB(mem, "MemAvailable", p.m.memAvailable)
	setKB(mem, "Cached", p.m.memCached)
}

// --- /proc/net/dev ----------------------------------------------------------
//
// Lines are "  iface: rxbytes rxpkts rxerrs rxdrop rxfifo rxframe rxcompressed
// rxmulticast txbytes txpkts txerrs txdrop txfifo txcolls txcarrier
// txcompressed". The two header lines have no colon and are skipped. Loopback
// is dropped; every other netdev is reported so a WAN device rename does not
// silently lose the series.
func (p *sshPoller) parseNetdev(s string) {
	p.m.ifRxBytes.Reset()
	p.m.ifTxBytes.Reset()
	p.m.ifRxPackets.Reset()
	p.m.ifTxPackets.Reset()
	p.m.ifRxErrors.Reset()
	p.m.ifTxErrors.Reset()
	p.m.ifRxDrops.Reset()
	p.m.ifTxDrops.Reset()

	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		iface := strings.TrimSpace(name)
		if skipIface(iface) {
			continue
		}
		f := strings.Fields(rest)
		if len(f) < 16 {
			continue
		}
		set := func(g *prometheus.GaugeVec, idx int) {
			if v, err := strconv.ParseFloat(f[idx], 64); err == nil {
				g.WithLabelValues(iface).Set(v)
			}
		}
		set(p.m.ifRxBytes, 0)
		set(p.m.ifRxPackets, 1)
		set(p.m.ifRxErrors, 2)
		set(p.m.ifRxDrops, 3)
		set(p.m.ifTxBytes, 8)
		set(p.m.ifTxPackets, 9)
		set(p.m.ifTxErrors, 10)
		set(p.m.ifTxDrops, 11)
	}
}

// --- conntrack --------------------------------------------------------------

func (p *sshPoller) parseConntrack(count, max string) {
	if v, ok := firstFloat(count); ok {
		p.m.conntrackCount.Set(v)
	}
	// CTMAX may print two lines (netfilter path then legacy sysctl); the first
	// numeric line wins.
	if v, ok := firstFloat(max); ok {
		p.m.conntrackMax.Set(v)
	}
}

// --- /sys/class/thermal -----------------------------------------------------
//
// Each line is "<type> <millidegrees>". The temp file is millidegrees C, so it
// is divided by 1000. A zone with no type still reports under its raw value's
// absence-safe label.
func (p *sshPoller) parseThermal(s string) {
	p.m.thermalC.Reset()
	seen := map[string]int{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		zone := f[0]
		milli, err := strconv.ParseFloat(f[len(f)-1], 64)
		if err != nil {
			continue
		}
		// Disambiguate duplicate zone types (e.g. two "cpu-thermal") with a suffix.
		seen[zone]++
		label := zone
		if seen[zone] > 1 {
			label = fmt.Sprintf("%s_%d", zone, seen[zone])
		}
		p.m.thermalC.WithLabelValues(label).Set(milli / 1000)
	}
}

// --- lsmod ------------------------------------------------------------------
//
// Reports a 0/1 for each module in nssModules. A module absent from lsmod reads
// 0, which is the meaningful state (offload engine not loaded), so every one is
// emitted rather than only the present ones.
func (p *sshPoller) parseLsmod(s string) {
	loaded := map[string]bool{}
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		loaded[f[0]] = true
	}
	p.m.nssModule.Reset()
	for _, mod := range nssModules {
		p.m.nssModule.WithLabelValues(mod).Set(boolToFloat(loaded[mod]))
	}
}

// --- tc -s qdisc show -------------------------------------------------------
//
// Output is blocks like:
//
//	qdisc cake 8011: dev eth1 root refcnt 2 bandwidth 100Mbit ...
//	 Sent 12345 bytes 67 pkt (dropped 8, overlimits 9 requeues 0)
//	 backlog 0b 0p requeues 0
//	 ... (cake-specific lines we ignore)
//
// We key on the "qdisc <kind> ... dev <iface>" line for the kind/iface, then
// read the immediately following "Sent ..." and "backlog ..." stat lines.
func (p *sshPoller) parseQdisc(s string) {
	p.m.qdiscInfo.Reset()
	p.m.qdiscSentBytes.Reset()
	p.m.qdiscSentPkts.Reset()
	p.m.qdiscDropped.Reset()
	p.m.qdiscOverlimit.Reset()
	p.m.qdiscBacklogB.Reset()
	p.m.qdiscBacklogP.Reset()

	var iface string
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "qdisc ") {
			kind, dev := parseQdiscHeader(line)
			iface = dev
			if iface != "" {
				p.m.qdiscInfo.WithLabelValues(iface, kind).Set(1)
			}
			continue
		}
		if iface == "" {
			continue
		}
		if strings.HasPrefix(line, "Sent ") {
			sent, pkts, dropped, over := parseSentLine(line)
			p.m.qdiscSentBytes.WithLabelValues(iface).Set(sent)
			p.m.qdiscSentPkts.WithLabelValues(iface).Set(pkts)
			p.m.qdiscDropped.WithLabelValues(iface).Set(dropped)
			p.m.qdiscOverlimit.WithLabelValues(iface).Set(over)
			continue
		}
		if strings.HasPrefix(line, "backlog ") {
			b, pk := parseBacklogLine(line)
			p.m.qdiscBacklogB.WithLabelValues(iface).Set(b)
			p.m.qdiscBacklogP.WithLabelValues(iface).Set(pk)
		}
	}
}

// parseQdiscHeader pulls the kind and dev out of a "qdisc <kind> <handle> dev
// <iface> ..." line. A qdisc line always names a device.
func parseQdiscHeader(line string) (kind, dev string) {
	f := strings.Fields(line)
	if len(f) >= 2 {
		kind = f[1]
	}
	for i := 0; i < len(f)-1; i++ {
		if f[i] == "dev" {
			dev = f[i+1]
			break
		}
	}
	return kind, dev
}

// parseSentLine reads "Sent <bytes> bytes <pkts> pkt (dropped <d>, overlimits
// <o> requeues <r>)".
func parseSentLine(line string) (sent, pkts, dropped, over float64) {
	f := strings.Fields(line)
	for i := 0; i < len(f); i++ {
		switch f[i] {
		case "Sent":
			if i+1 < len(f) {
				sent = atofSafe(f[i+1])
			}
		case "bytes":
			if i+1 < len(f) {
				pkts = atofSafe(f[i+1])
			}
		case "(dropped":
			if i+1 < len(f) {
				dropped = atofSafe(strings.TrimRight(f[i+1], ","))
			}
		case "overlimits":
			if i+1 < len(f) {
				over = atofSafe(f[i+1])
			}
		}
	}
	return sent, pkts, dropped, over
}

// parseBacklogLine reads "backlog <N>b <M>p requeues <r>".
func parseBacklogLine(line string) (bytes, pkts float64) {
	f := strings.Fields(line)
	for _, tok := range f {
		if strings.HasSuffix(tok, "b") && len(tok) > 1 {
			if v, err := strconv.ParseFloat(strings.TrimSuffix(tok, "b"), 64); err == nil {
				bytes = v
			}
		}
		if strings.HasSuffix(tok, "p") && len(tok) > 1 {
			if v, err := strconv.ParseFloat(strings.TrimSuffix(tok, "p"), 64); err == nil {
				pkts = v
			}
		}
	}
	return bytes, pkts
}

// --- ubus network.interface.wan status --------------------------------------

func (p *sshPoller) parseWAN(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	var st struct {
		Up     bool    `json:"up"`
		Uptime float64 `json:"uptime"`
	}
	if err := json.Unmarshal([]byte(s), &st); err != nil {
		log.Printf("ssh poll: parse wan status: %v", err)
		return
	}
	p.m.wanUp.Set(boolToFloat(st.Up))
	p.m.wanUptime.Set(st.Uptime)
}

// --- shared helpers ---------------------------------------------------------

// virtualIfacePrefixes are software/virtual netdevs whose /proc/net/dev byte
// counters are noise: ingress-shaping mirrors (ifb) and tunnel devices carry no
// real per-link traffic signal, and a router running sqm has dozens of ifb*.
// Their qdisc stats, where they matter (ingress CAKE lives on an ifb), are
// still reported by the tc collector - only the redundant netdev counters are
// dropped.
var virtualIfacePrefixes = []string{"ifb", "gre", "gretap", "sit", "tunl", "ip6tnl", "ip6gre", "teql", "erspan", "ip_vti", "ip6_vti"}

// skipIface reports whether a netdev should be dropped from the per-interface
// counters: loopback and the virtual-noise devices above.
func skipIface(name string) bool {
	if name == "" || name == "lo" {
		return true
	}
	for _, p := range virtualIfacePrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func atofSafe(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v
}

// firstFloat returns the first whitespace-separated float in s.
func firstFloat(s string) (float64, bool) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// parseKV parses "Key: value ..." lines into Key -> "value ...".
func parseKV(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		m[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return m
}

// setKB reads a "<number> kB" value and sets the gauge in bytes.
func setKB(m map[string]string, key string, g prometheus.Gauge) {
	v, ok := m[key]
	if !ok {
		return
	}
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return
	}
	n, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return
	}
	g.Set(n * 1024)
}

// loadSSHConfig builds the SSH collector config from the environment. SSH is the
// primary path, so PR60X_SSH_ADDR being set is the contract; the key file is
// then required.
func loadSSHConfig(interval, timeout time.Duration) (*sshConfig, error) {
	addr := os.Getenv("PR60X_SSH_ADDR")
	if addr == "" {
		return nil, nil
	}
	keyFile := os.Getenv("PR60X_SSH_KEY_FILE")
	if keyFile == "" {
		return nil, fmt.Errorf("PR60X_SSH_ADDR is set but PR60X_SSH_KEY_FILE is empty")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", keyFile, err)
	}
	cfg := &sshConfig{
		addr:     addr,
		user:     envOr("PR60X_SSH_USER", "root"),
		keyPEM:   keyPEM,
		interval: interval,
		timeout:  timeout,
	}
	if hk := os.Getenv("PR60X_SSH_HOSTKEY"); hk != "" {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk))
		if err != nil {
			return nil, fmt.Errorf("parse PR60X_SSH_HOSTKEY: %w", err)
		}
		cfg.hostKey = pk
	}
	return cfg, nil
}
