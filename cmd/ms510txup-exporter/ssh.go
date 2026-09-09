// Root-shell /proc telemetry for the MS510TXUP - the ONLY data path this
// exporter has. It reads the RealTek RTL93xx driver's /proc tree over the
// dropbear root shell (:2222, ECDSA key auth). There is deliberately NO web CGI
// path: this switch carries the whole k8s cluster and its embedded web server
// has a 4-slot session table that locks out the UI (and Terraform) once it
// fills, so the exporter must hold ZERO web sessions. Everything below comes
// from root /proc instead, which costs no session at all.
//
// WHAT /proc EXPOSES (and the web UI hides)
// -----------------------------------------
//   - /proc/hwmon/portmib/<port> - per-port MIB COUNTER samplers: rx/tx bytes,
//     rx/tx packets, rx/tx multicast+broadcast packets. These are the live
//     throughput/traffic counters. They ship DISABLED and are turned on
//     out-of-band by ansible (roles/ms510_port_samplers in the private ansible
//     repo) - this exporter only READS them (see the SAFETY note). Whether a
//     sampler is on is read from /proc/switch/hwmon.status and exported as
//     ms510txup_proc_sampler_enabled so a post-reboot gap (the enable is
//     RAM-only) is visible.
//   - /proc/linkdown - per-port link-down REASON ring with real timestamps.
//     Says WHY a port bounced (SW-AdminDown, HW-NoCableDetected, ...) and WHEN,
//     which is what root-causes an etcd/Longhorn stall - and what powers the
//     inter-switch uplink flap alert (the newest reason timestamp is exported).
//   - /proc/poe      - the SDK's own PoE view: delivered/max power, negotiated
//     class, delivering-vs-searching, and the global budget/consumed.
//   - /proc/optical  - raw SFP EEPROM for the two SFP+ cages (vendor, part,
//     presence, whether the optic implements DDM).
//   - /proc/vlan     - VLAN membership and per-port PVID.
//
// WHAT WAS DROPPED with the CGI path, and why it can't come back over SSH:
//   - per-port LINK up/speed/duplex: not in /proc. /proc/linkdown "(cur: N)" is
//     the linkdown-ring write pointer, NOT a link-up flag (a busy port reads
//     cur:0), and the PHY sampler exposes only raw PHY registers.
//   - per-port ERROR/DISCARD/COLLISION counters: the portmib sampler's fixed
//     counter set (conf index 2) has none. rate() over the byte/packet counters
//     plus the /proc/linkdown reason ring cover the operational need.
//   - STP state and EEE/green-ethernet: neither is in /proc (only the CLI shows
//     them, and the CLI needs a pty it will not give a non-interactive exec).
//     These were all CGI-only, so keeping them meant keeping a web session, which
//     is exactly what this exporter now refuses to do.
//
// SAFETY - READ-ONLY /proc ONLY
// -----------------------------
// Every command this collector runs is a passive read (`cat`/`grep` of /proc).
// It never writes a register, never enables a sampler (that enable lives in
// ansible, applied deliberately over root - not here), and never touches the
// CLI or the SDK diag shell. The RTL93xx data-plane knobs are not writable via
// /proc anyway; the diag binary is absent on the production image. Keep it that
// way: this is a metrics collector, it has no business mutating the cluster
// switch. See netgear-certs/research/ms510-root-unlocks.md.
//
// NO THERMAL: the RTL93xx die temperature is not exposed to Linux on this image
// (no /sys/class/thermal, and /proc/hwmon is the port/PHY/SFP monitor, not a
// CPU/ASIC thermal zone), so there is deliberately no temperature gauge here.
//
// FIRMWARE DEPENDENCY: root SSH exists only because this unit runs a modified
// image with dropbear added on :2222. Revert to stock and the shell disappears
// and this exporter goes dark (ms510txup_ssh_up 0) - it has no other data path.
package main

import (
	"bufio"
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
	addr     string // host:port, e.g. switch.lan:2222
	user     string
	keyPEM   []byte
	hostKey  ssh.PublicKey // nil => accept any (LAN device)
	interval time.Duration
	timeout  time.Duration
}

// sshMetrics are the /proc-sourced gauges - the exporter's entire metric set,
// since the CGI collector was removed. Everything /proc-sourced carries a proc_
// name segment, both as an honest source marker and so the families stay
// distinct (e.g. proc_poe_* is the SDK controller's own PoE view).
type sshMetrics struct {
	up            prometheus.Gauge
	scrapeSeconds prometheus.Gauge
	scrapeErrors  prometheus.Counter

	// /proc/hwmon/portmib/<port> - per-port MIB counter samplers.
	rxBytes         *prometheus.GaugeVec
	txBytes         *prometheus.GaugeVec
	rxPackets       *prometheus.GaugeVec
	txPackets       *prometheus.GaugeVec
	rxMcastBcast    *prometheus.GaugeVec
	txMcastBcast    *prometheus.GaugeVec
	counterSampleTS *prometheus.GaugeVec
	samplerEnabled  *prometheus.GaugeVec

	// /proc/linkdown - per-port link-down reason ring.
	linkdownEvents *prometheus.GaugeVec
	linkdownReason *prometheus.GaugeVec
	linkdownLastTS *prometheus.GaugeVec

	// /proc/poe - the SDK controller's own PoE view.
	poeBudgetMW    prometheus.Gauge
	poeConsumedMW  prometheus.Gauge
	poePortPowerMW *prometheus.GaugeVec
	poePortMaxMW   *prometheus.GaugeVec
	poePortClass   *prometheus.GaugeVec
	poePortDeliver *prometheus.GaugeVec

	// /proc/optical - raw SFP EEPROM for the SFP+ cages.
	sfpPresent *prometheus.GaugeVec
	sfpDDM     *prometheus.GaugeVec
	sfpInfo    *prometheus.GaugeVec

	// /proc/vlan - VLAN membership and per-port PVID.
	vlanMember *prometheus.GaugeVec
	portPVID   *prometheus.GaugeVec
}

func newSSHMetrics(reg prometheus.Registerer) *sshMetrics {
	f := factory{reg}
	return &sshMetrics{
		up: f.gauge("ssh_up", "1 if the last root-shell /proc poll succeeded. 0 means the dropbear "+
			"root shell was unreachable (or the switch was reverted to stock firmware) - and since this "+
			"exporter is SSH-only, a 0 means no fresh metrics at all. THE availability signal to alert on."),
		scrapeSeconds: f.gauge("ssh_scrape_duration_seconds", "Duration of the last root-shell /proc poll."),
		scrapeErrors:  f.counter("ssh_scrape_errors_total", "Failed root-shell /proc polls."),

		rxBytes: f.vec("proc_port_rx_bytes", "Bytes received on the port (ingress, device->switch), from the "+
			"/proc/hwmon/portmib/<port> MIB sampler. NOTE: this is a 32-bit counter that WRAPS at ~4 GiB - use "+
			"rate()/increase(), and watch proc_port_counter_sample_timestamp_seconds for a stalled sampler. Zero for a "+
			"port whose sampler is disabled (see proc_sampler_enabled).", "port"),
		txBytes: f.vec("proc_port_tx_bytes", "Bytes transmitted on the port (egress, switch->device), from the "+
			"/proc/hwmon/portmib sampler. 32-bit, wraps at ~4 GiB - use rate()/increase().", "port"),
		rxPackets: f.vec("proc_port_rx_packets", "Packets received on the port (ingress, device->switch), from "+
			"the /proc/hwmon/portmib sampler.", "port"),
		txPackets: f.vec("proc_port_tx_packets", "Packets transmitted on the port (egress, switch->device), from "+
			"the /proc/hwmon/portmib sampler.", "port"),
		rxMcastBcast: f.vec("proc_port_rx_multicast_broadcast_packets", "Multicast+broadcast packets received on "+
			"the port (ingress from the device). Low and device-specific; contrast with the tx side, which carries "+
			"the whole broadcast domain's flood.", "port"),
		txMcastBcast: f.vec("proc_port_tx_multicast_broadcast_packets", "Multicast+broadcast packets transmitted "+
			"on the port (egress toward the device) - dominated by the broadcast flood copied to every port, so it "+
			"reads similarly across ports in the same VLAN.", "port"),
		counterSampleTS: f.vec("proc_port_counter_sample_timestamp_seconds", "Unix time of the newest "+
			"/proc/hwmon/portmib ring sample for the port. time()-this is the sampler's staleness: it should track "+
			"the sampler period (10s). A value stuck in the past means the sampler stopped (e.g. lost after a "+
			"reboot before ansible re-applied the enable).", "port"),
		samplerEnabled: f.vec("proc_sampler_enabled", "1 if the per-port MIB counter sampler is enabled, read "+
			"from /proc/switch/hwmon.status. The enable is applied out-of-band by ansible and is RAM-only, so this "+
			"drops to 0 across a reboot until ansible re-runs - alert on it to catch a silent counter gap.", "port"),

		linkdownEvents: f.vec("proc_port_linkdown_logged_events", "Number of real (non-Unknown) entries in "+
			"the RealTek driver's per-port link-down REASON ring at /proc/linkdown (the ring holds the last 8). "+
			"Evidence the ring actually recorded a reason; proc_port_linkdown_reason_info carries WHY and "+
			"proc_port_linkdown_last_timestamp_seconds carries WHEN.", "port"),
		linkdownReason: f.vec("proc_port_linkdown_reason_info", "Always 1. The most recent non-Unknown "+
			"link-down reason for the port, as the driver names it (e.g. SW-AdminDown, HW-NoCableDetected), carried "+
			"as a label. 'none' when the ring holds no real reason.", "port", "reason"),
		linkdownLastTS: f.vec("proc_port_linkdown_last_timestamp_seconds", "Unix time of the MOST RECENT "+
			"non-Unknown link-down entry in /proc/linkdown for the port, 0 if none. This is the flap signal to "+
			"alert on: time()-this is 'seconds since last flap', and changes(...[window]) counts distinct flaps in "+
			"the window even though the ring only holds 8. The inter-switch SFP+ uplink (port 9, xg9) logging "+
			"HW-NoCableDetected repeatedly is a failing/loose DAC.", "port"),

		poeBudgetMW:   f.gauge("proc_poe_budget_milliwatts", "Global PoE power budget from /proc/poe, in mW - the SDK controller's own figure."),
		poeConsumedMW: f.gauge("proc_poe_consumed_milliwatts", "Global PoE power currently consumed from /proc/poe, in mW - the SDK controller's own measurement."),
		poePortPowerMW: f.vec("proc_poe_port_power_milliwatts", "Power delivered on the port from /proc/poe, in mW. "+
			"The RealTek controller's own reading, distinct from the CGI poe_port_power_watts.", "port"),
		poePortMaxMW: f.vec("proc_poe_port_max_power_milliwatts", "Per-port max power ceiling from /proc/poe, in mW.", "port"),
		poePortClass: f.vec("proc_poe_port_class", "Negotiated 802.3bt class from /proc/poe.", "port"),
		poePortDeliver: f.vec("proc_poe_port_delivering", "1 if /proc/poe lists the port as delivering power, "+
			"0 if it is searching/idle. The controller's ground truth for whether a powered node is actually up.", "port"),

		sfpPresent: f.vec("proc_sfp_present", "1 if an SFP module is seated in the cage (EEPROM identifier reads as SFP), from /proc/optical.", "port"),
		sfpDDM: f.vec("proc_sfp_ddm_supported", "1 if the seated SFP implements digital diagnostics (DDM/DOM). "+
			"The current SFP-H10GB-CU direct-attach copper cables do NOT, so live temp/power is unavailable "+
			"until a real optic is fitted - this flag says whether that data would exist.", "port"),
		sfpInfo: f.vec("proc_sfp_info", "Always 1. SFP vendor and part number decoded from the raw EEPROM in /proc/optical.", "port", "vendor", "part_number"),

		vlanMember: f.vec("proc_vlan_port_membership", "How a front-panel port belongs to a VLAN, from /proc/vlan: "+
			"1 untagged, 2 tagged (the same encoding the web API uses). A port absent from a VLAN has no series "+
			"for it. Sourced from the root /proc read, so it costs no web session - this is the storage VLAN's "+
			"membership (VLAN 20 tagged on the node ports and the SFP+ uplink) made visible without the CGI.",
			"vlan", "port"),
		portPVID: f.vec("proc_port_pvid", "The port's PVID from /proc/vlan - the VLAN untagged ingress traffic "+
			"lands on. Exported so a PVID drifting off 1 (which silently reclassifies a node's untagged traffic) "+
			"is visible.", "port"),
	}
}

// sshPoller owns the /proc-side collection. Like the CGI poller it runs on its
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
// switch's small single-core management plane.
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
	p.parsePoE(sec["POE"])
	p.parseLinkdown(sec["LINKDOWN"])
	p.parseOptical(sec["OPTICAL"])
	p.parseVLAN(sec["VLAN"])
	p.parseHwmonStatus(sec["HWMON"])
	p.parseMIB(sec["MIB"])
	p.m.up.Set(1)
}

// mibPorts are the front-panel port sampler files under /proc/hwmon/portmib,
// in front-panel order. The trailing digits are the port label (mg1..xg10 =
// 1..10), matching the rest of this exporter's port label space.
var mibPorts = []string{"mg1", "mg2", "mg3", "mg4", "xmg5", "xmg6", "xmg7", "xmg8", "xg9", "xg10"}

// sshBatch is the ENTIRE set of commands this collector will ever run. Every
// line is a passive read - see the safety note at the top of the file before
// adding. The portmib reads take only the newest ring row (0000) per port to
// keep the single session's output small.
var sshBatch = buildSSHBatch()

func buildSSHBatch() string {
	var b strings.Builder
	b.WriteString(`echo @@POE; cat /proc/poe 2>/dev/null; `)
	b.WriteString(`echo @@LINKDOWN; cat /proc/linkdown 2>/dev/null; `)
	b.WriteString(`echo @@OPTICAL; cat /proc/optical 2>/dev/null; `)
	b.WriteString(`echo @@VLAN; cat /proc/vlan 2>/dev/null; `)
	b.WriteString(`echo @@HWMON; cat /proc/switch/hwmon.status 2>/dev/null; `)
	b.WriteString(`echo @@MIB; `)
	for _, p := range mibPorts {
		// One "port <name>" marker then that port's newest sample row. grep is
		// a passive read; if the sampler is disabled the row is absent, which
		// the parser tolerates.
		fmt.Fprintf(&b, `echo "port %s"; grep '^0000:' /proc/hwmon/portmib/%s 2>/dev/null; `, p, p)
	}
	b.WriteString(`echo @@DONE`)
	return b.String()
}

// collect dials, authenticates, runs the batch over a single session and
// returns the combined output.
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

// splitSSHSections carves the output on the @@NAME markers the batch emits.
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

// --- /proc/poe --------------------------------------------------------------
//
// The file has three parts we read: a global block (Power Budget / Power
// Consumed), a "Delivering Power" table (port power max class ...), and an
// "Others" table (port status ...). We stop before the per-port status logs.
func (p *sshPoller) parsePoE(s string) {
	if s == "" {
		return
	}
	p.m.poePortPowerMW.Reset()
	p.m.poePortMaxMW.Reset()
	p.m.poePortClass.Reset()
	p.m.poePortDeliver.Reset()

	const (
		secNone = iota
		secDelivering
		secOthers
	)
	state := secNone

	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Power Budget"):
			if v, ok := firstIntAfterColon(line); ok {
				p.m.poeBudgetMW.Set(float64(v))
			}
			continue
		case strings.HasPrefix(line, "Power Consumed"):
			if v, ok := firstIntAfterColon(line); ok {
				p.m.poeConsumedMW.Set(float64(v))
			}
			continue
		case strings.Contains(line, "Delivering Power"):
			state = secDelivering
			continue
		case strings.Contains(line, "(Others)"):
			state = secOthers
			continue
		case strings.Contains(line, "Status Logs"):
			// Past the tables; nothing more to read for gauges.
			return
		}
		if line == "" || strings.HasPrefix(line, "|") || strings.HasPrefix(line, "=") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		port, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		label := strconv.Itoa(port)

		switch state {
		case secDelivering:
			// port power max class description...
			if len(fields) < 4 {
				continue
			}
			if v, err := strconv.Atoi(fields[1]); err == nil {
				p.m.poePortPowerMW.WithLabelValues(label).Set(float64(v))
			}
			if v, err := strconv.Atoi(fields[2]); err == nil {
				p.m.poePortMaxMW.WithLabelValues(label).Set(float64(v))
			}
			if v, err := strconv.Atoi(fields[3]); err == nil {
				p.m.poePortClass.WithLabelValues(label).Set(float64(v))
			}
			p.m.poePortDeliver.WithLabelValues(label).Set(1)
		case secOthers:
			// port status startup-mode max-power - not delivering.
			p.m.poePortPowerMW.WithLabelValues(label).Set(0)
			p.m.poePortDeliver.WithLabelValues(label).Set(0)
		}
	}
}

// --- /proc/linkdown ---------------------------------------------------------
//
// Blocks of:
//
//	port MultiGigabitEthernet4 (cur: 1):
//	  tmp reason:
//	    <ts> (<code>)<Reason>
//	  reason log:
//	    <ts> (<code>)<Reason>
//	    0.000000000 (0)Unknown        <- empty ring slot
//	    ...
//
// We count the non-Unknown entries in the reason log (real recorded reasons)
// and carry the most recent one as a label.
func (p *sshPoller) parseLinkdown(s string) {
	if s == "" {
		return
	}
	p.m.linkdownEvents.Reset()
	p.m.linkdownReason.Reset()
	p.m.linkdownLastTS.Reset()

	var (
		port     string
		inLog    bool
		count    int
		lastReas string
		lastTS   float64
	)
	flush := func() {
		if port == "" {
			return
		}
		p.m.linkdownEvents.WithLabelValues(port).Set(float64(count))
		if lastReas == "" {
			lastReas = "none"
		}
		p.m.linkdownReason.WithLabelValues(port, lastReas).Set(1)
		p.m.linkdownLastTS.WithLabelValues(port).Set(lastTS)
	}

	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "port ") && strings.Contains(trimmed, "(cur:") {
			flush()
			port = portNumFromName(trimmed)
			inLog = false
			count = 0
			lastReas = ""
			lastTS = 0
			continue
		}
		if strings.HasPrefix(trimmed, "reason log") {
			inLog = true
			continue
		}
		if strings.HasPrefix(trimmed, "tmp reason") {
			inLog = false
			continue
		}
		if !inLog || trimmed == "" {
			continue
		}
		// A reason entry: "<ts> (<code>)<Reason>". Empty slots read
		// "0.000000000 (0)Unknown".
		reason, ts, ok := parseReasonEntry(trimmed)
		if !ok {
			continue
		}
		count++
		if lastReas == "" {
			// Entries are newest-first, so the first real one is the most
			// recent flap - its reason and timestamp both win.
			lastReas = reason
			lastTS = ts
		}
	}
	flush()
}

// parseReasonEntry returns the reason text and Unix timestamp (seconds) of a
// link-down ring entry, and false if the entry is an empty slot (timestamp 0 /
// "Unknown"). The driver prints the timestamp as "<sec>.<nanos>".
func parseReasonEntry(s string) (string, float64, bool) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return "", 0, false
	}
	// fields[0] is the timestamp; 0.000000000 marks an empty slot.
	if strings.HasPrefix(fields[0], "0.000000000") {
		return "", 0, false
	}
	ts, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return "", 0, false
	}
	// The rest is "(code)Reason" possibly with spaces in the reason.
	rest := strings.TrimSpace(strings.Join(fields[1:], " "))
	if i := strings.Index(rest, ")"); i >= 0 && strings.HasPrefix(rest, "(") {
		rest = rest[i+1:]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" || strings.EqualFold(rest, "Unknown") {
		return "", 0, false
	}
	return rest, ts, true
}

// --- /proc/optical ----------------------------------------------------------
//
// Blocks of:
//
//	Port xg9:
//	000: 03 04 21 00 ...    ...    ..!.
//	016: ...
//
// The hex is the raw SFF-8472 A0h EEPROM. We rebuild the byte array from the
// leading offsets and decode identifier/vendor/part/DDM-flag.
func (p *sshPoller) parseOptical(s string) {
	if s == "" {
		return
	}
	p.m.sfpPresent.Reset()
	p.m.sfpDDM.Reset()
	p.m.sfpInfo.Reset()

	var (
		port    string
		eeprom  = make(map[int]byte)
		haveAny bool
	)
	flush := func() {
		if port == "" {
			return
		}
		p.emitOptical(port, eeprom, haveAny)
	}

	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Port ") && strings.HasSuffix(trimmed, ":") {
			flush()
			port = portNumFromName(trimmed)
			eeprom = make(map[int]byte)
			haveAny = false
			continue
		}
		// Data line: "NNN: h h h h  h h h h   ascii". Take the offset then the
		// two-hex-digit tokens.
		off, bytes, ok := parseHexDumpLine(trimmed)
		if !ok {
			continue
		}
		for i, b := range bytes {
			eeprom[off+i] = b
			haveAny = true
		}
	}
	flush()
}

func (p *sshPoller) emitOptical(port string, eeprom map[int]byte, haveAny bool) {
	if !haveAny {
		p.m.sfpPresent.WithLabelValues(port).Set(0)
		return
	}
	// Byte 0: identifier. 0x03 = SFP/SFP+.
	present := eeprom[0] == 0x03
	p.m.sfpPresent.WithLabelValues(port).Set(b2f(present))
	if !present {
		return
	}
	// Byte 92: diagnostic monitoring type; bit 6 (0x40) = DDM implemented.
	ddm := eeprom[92]&0x40 != 0
	p.m.sfpDDM.WithLabelValues(port).Set(b2f(ddm))

	vendor := eepromString(eeprom, 20, 35)
	part := eepromString(eeprom, 40, 55)
	p.m.sfpInfo.WithLabelValues(port, vendor, part).Set(1)
}

// eepromString reads an inclusive ASCII byte range and trims the trailing
// spaces SFF fields are padded with.
func eepromString(eeprom map[int]byte, lo, hi int) string {
	var b strings.Builder
	for i := lo; i <= hi; i++ {
		c, ok := eeprom[i]
		if !ok || c < 0x20 || c > 0x7e {
			continue
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

// parseHexDumpLine parses "NNN: b0 b1 ... [ascii]" into its starting offset and
// the byte values. It stops at the first token that is not a 2-hex-digit byte,
// which is where the ASCII gutter begins.
func parseHexDumpLine(s string) (int, []byte, bool) {
	colon := strings.Index(s, ":")
	if colon <= 0 {
		return 0, nil, false
	}
	off, err := strconv.Atoi(strings.TrimSpace(s[:colon]))
	if err != nil {
		return 0, nil, false
	}
	var out []byte
	for _, tok := range strings.Fields(s[colon+1:]) {
		if len(tok) != 2 {
			break
		}
		v, err := strconv.ParseUint(tok, 16, 8)
		if err != nil {
			break
		}
		out = append(out, byte(v))
		if len(out) >= 128 {
			break
		}
	}
	if len(out) == 0 {
		return 0, nil, false
	}
	return off, out, true
}

// --- /proc/vlan -------------------------------------------------------------
//
// Two blocks. First a membership table, one row per VLAN:
//
//	vid(group id): utagged member| tagged member
//	1(1): mg1-4,xmg5-8,xg9-10 |
//	20(1):  | mg1-4,xg10
//
// then a PVID block:
//
//	PVID
//	MultiGigabitEthernet1: 1
//	...
//
// The port names carry the front-panel number as their trailing digits
// (mg1..mg4 = 1..4, xmg5..xmg8 = 5..8, xg9..xg10 = 9..10), and the membership
// lists use those same numbers, so a range like "xmg5-8" expands to ports 5-8.
func (p *sshPoller) parseVLAN(s string) {
	if s == "" {
		return
	}
	p.m.vlanMember.Reset()
	p.m.portPVID.Reset()

	inPVID := false
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "PVID") {
			inPVID = true
			continue
		}
		if inPVID {
			name, val, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			port := portNumFromName(strings.TrimSpace(name))
			v, err := strconv.Atoi(strings.TrimSpace(val))
			if err != nil || port == "" {
				continue
			}
			p.m.portPVID.WithLabelValues(port).Set(float64(v))
			continue
		}

		head, members, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		// "1(1)" -> "1"; the header row's "vid(group id)" fails the Atoi and is
		// skipped without a special case.
		if i := strings.Index(head, "("); i >= 0 {
			head = head[:i]
		}
		vid := strings.TrimSpace(head)
		if _, err := strconv.Atoi(vid); err != nil {
			continue
		}
		untag, tag, _ := strings.Cut(members, "|")
		// 1 = untagged, 2 = tagged, matching the web API's own encoding.
		for _, port := range expandPortList(untag) {
			p.m.vlanMember.WithLabelValues(vid, port).Set(1)
		}
		for _, port := range expandPortList(tag) {
			p.m.vlanMember.WithLabelValues(vid, port).Set(2)
		}
	}
}

// expandPortList turns a /proc/vlan member list like "mg1-4,xmg5-8,xg10" into
// the front-panel port numbers it covers. The alphabetic prefix is dropped and
// each token is either a single number or an inclusive N-M range.
func expandPortList(s string) []string {
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// Drop the leading letters (mg / xmg / xg / lag), leaving "1-4", "10".
		i := 0
		for i < len(tok) && (tok[i] < '0' || tok[i] > '9') {
			i++
		}
		nums := tok[i:]
		if lo, hi, ok := strings.Cut(nums, "-"); ok {
			a, err1 := strconv.Atoi(strings.TrimSpace(lo))
			b, err2 := strconv.Atoi(strings.TrimSpace(hi))
			if err1 != nil || err2 != nil || a > b {
				continue
			}
			for n := a; n <= b; n++ {
				out = append(out, strconv.Itoa(n))
			}
			continue
		}
		if _, err := strconv.Atoi(nums); err == nil {
			out = append(out, nums)
		}
	}
	return out
}

// --- /proc/switch/hwmon.status ----------------------------------------------
//
// The portmib block reads:
//
//	portmib:
//	  mg1 enabled: 1, period: 10
//	  mg2 enabled: 0
//	  ...
//
// We emit proc_sampler_enabled for the front-panel ports only (the phy/sfp/lag
// entries in the same file are skipped - they carry names like "0.0"/"lag1"
// that are not in mibPorts).
func (p *sshPoller) parseHwmonStatus(s string) {
	if s == "" {
		return
	}
	p.m.samplerEnabled.Reset()
	want := map[string]bool{}
	for _, name := range mibPorts {
		want[name] = true
	}
	for _, raw := range strings.Split(s, "\n") {
		fields := strings.Fields(strings.TrimSpace(raw))
		if len(fields) < 3 || !want[fields[0]] || fields[1] != "enabled:" {
			continue
		}
		// fields[2] is "1" or "0", possibly with a trailing comma ("1,").
		v := strings.TrimSuffix(fields[2], ",")
		p.m.samplerEnabled.WithLabelValues(portNumFromName(fields[0])).Set(b2f(v == "1"))
	}
}

// --- /proc/hwmon/portmib/<port> ---------------------------------------------
//
// The batch prints, per port, a marker line and that port's newest ring row:
//
//	port mg4
//	0000: <unix_ts>.<nanos> <c0hi> <c0lo> <c1hi> <c1lo> ... <c5hi> <c5lo>
//
// Each of the six counters is a 64-bit value split into two 32-bit hex words
// (high, low). The counter set (RTL93xx hwmon conf index 2) is, in order:
// rx packets, rx mcast+bcast, rx bytes, tx packets, tx mcast+bcast, tx bytes -
// where rx is ingress (device->switch) and tx is egress (switch->device).
// Direction was confirmed on the device: the tx mcast+bcast counter reads
// uniformly across ports (the broadcast flood copied to every egress) while the
// rx one is device-specific. The byte counters are 32-bit and wrap.
func (p *sshPoller) parseMIB(s string) {
	if s == "" {
		return
	}
	p.m.rxBytes.Reset()
	p.m.txBytes.Reset()
	p.m.rxPackets.Reset()
	p.m.txPackets.Reset()
	p.m.rxMcastBcast.Reset()
	p.m.txMcastBcast.Reset()
	p.m.counterSampleTS.Reset()

	var port string
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "port ") {
			port = portNumFromName(line)
			continue
		}
		if port == "" || !strings.HasPrefix(line, "0000:") {
			continue
		}
		ts, c, ok := parseMIBRow(line)
		if !ok {
			continue
		}
		p.m.rxPackets.WithLabelValues(port).Set(c[0])
		p.m.rxMcastBcast.WithLabelValues(port).Set(c[1])
		p.m.rxBytes.WithLabelValues(port).Set(c[2])
		p.m.txPackets.WithLabelValues(port).Set(c[3])
		p.m.txMcastBcast.WithLabelValues(port).Set(c[4])
		p.m.txBytes.WithLabelValues(port).Set(c[5])
		p.m.counterSampleTS.WithLabelValues(port).Set(ts)
		port = "" // one row per port
	}
}

// parseMIBRow parses a "0000: <ts> <hi lo>x6" ring row into the sample
// timestamp (seconds) and the six 64-bit counters. Returns false if the line is
// not a full row (e.g. a disabled sampler that printed nothing).
func parseMIBRow(s string) (float64, [6]float64, bool) {
	var c [6]float64
	fields := strings.Fields(s)
	// fields[0]="0000:", fields[1]=timestamp, then 12 hex words.
	if len(fields) < 2+12 {
		return 0, c, false
	}
	ts, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return 0, c, false
	}
	for i := 0; i < 6; i++ {
		hi, err1 := strconv.ParseUint(fields[2+i*2], 16, 64)
		lo, err2 := strconv.ParseUint(fields[2+i*2+1], 16, 64)
		if err1 != nil || err2 != nil {
			return 0, c, false
		}
		c[i] = float64(hi<<32 | lo)
	}
	return ts, c, true
}

// --- shared helpers ---------------------------------------------------------

// portNumFromName pulls the trailing port number out of an interface name like
// "MultiGigabitEthernet4", "XGigabitEthernet9" or "xg10", so /proc metrics
// share the 1..10 port label space the CGI metrics use.
func portNumFromName(s string) string {
	// Strip the "port " / "(cur:...)" / "Port ... :" chrome first.
	s = strings.TrimSuffix(strings.TrimSpace(s), ":")
	if i := strings.Index(s, "("); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	// Take the token after any whitespace (e.g. "port MultiGigabitEthernet4").
	if fields := strings.Fields(s); len(fields) > 0 {
		s = fields[len(fields)-1]
	}
	// Trailing digits.
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return s // no trailing digits; return as-is rather than empty
	}
	return s[i:]
}

// firstIntAfterColon reads the first integer following a colon, e.g.
// "Power Budget    : 280200 mW" -> 280200.
func firstIntAfterColon(s string) (int, bool) {
	_, after, ok := strings.Cut(s, ":")
	if !ok {
		return 0, false
	}
	fields := strings.Fields(after)
	if len(fields) == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, false
	}
	return v, true
}

// loadSSHConfig builds the SSH collector config from the environment, or returns
// (nil, nil) when MS510TXUP_SSH_ADDR is unset (collector disabled).
func loadSSHConfig(interval, timeout time.Duration) (*sshConfig, error) {
	addr := os.Getenv("MS510TXUP_SSH_ADDR")
	if addr == "" {
		return nil, nil
	}
	keyFile := os.Getenv("MS510TXUP_SSH_KEY_FILE")
	if keyFile == "" {
		return nil, fmt.Errorf("MS510TXUP_SSH_ADDR is set but MS510TXUP_SSH_KEY_FILE is empty")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", keyFile, err)
	}
	cfg := &sshConfig{
		addr:     addr,
		user:     envOr("MS510TXUP_SSH_USER", "sshd"),
		keyPEM:   keyPEM,
		interval: interval,
		timeout:  timeout,
	}
	// Optional pinned host key ("ecdsa-sha2-nistp256 AAAA..." line). Unset =
	// accept any, acceptable for a LAN appliance.
	if hk := os.Getenv("MS510TXUP_SSH_HOSTKEY"); hk != "" {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk))
		if err != nil {
			return nil, fmt.Errorf("parse MS510TXUP_SSH_HOSTKEY: %w", err)
		}
		cfg.hostKey = pk
	}
	return cfg, nil
}
