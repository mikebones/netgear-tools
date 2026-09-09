// Root-shell /proc telemetry for the MS510TXUP, read over SSH rather than the
// web CGI API.
//
// WHY THIS EXISTS, AND WHAT THE WEB API CANNOT SEE
// ------------------------------------------------
// The CGI API (the rest of this exporter) is a good source for port config,
// counters, PoE and STP, but it surfaces almost none of what the RealTek
// RTL93xx driver publishes under /proc. Root on this switch (dropbear on :2222,
// ECDSA key auth) opens a rich READ-ONLY /proc tree the smart-managed UI hides:
//
//   - /proc/linkdown - per-port link-down REASON ring buffer. The web API's
//     linkDownEvent is a bare count; this says WHY a port bounced (SW-AdminDown,
//     LinkFault, ...), which is what actually root-causes an etcd/Longhorn stall.
//   - /proc/poe      - the SDK's own PoE view: delivered/max power, negotiated
//     class, delivering-vs-searching, and the global budget/consumed. This is
//     the authoritative controller reading, distinct from the CGI poe_* metrics.
//   - /proc/optical  - raw SFP EEPROM for the two SFP+ cages (vendor, part,
//     presence, whether the optic implements DDM).
//
// This collector is gated entirely on MS510TXUP_SSH_ADDR being set. Leave it
// unset and the exporter behaves exactly as before: CGI only. An SSH failure
// never touches the CGI metrics - it sets ms510txup_ssh_up to 0 and leaves the
// last-known /proc gauges in place.
//
// SAFETY - READ-ONLY /proc ONLY
// -----------------------------
// Every command this collector runs is a passive `cat /proc/*`. It never writes
// a register, never enables a sampler (the /proc/hwmon/* ring buffers ship
// disabled and enabling them is a WRITE - not done here), and never touches the
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
// and this collector goes dark - the graceful-degradation case above.
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

// sshMetrics are the /proc-sourced gauges. They live on the same registry as
// the CGI metrics but in their own struct so the two collectors never reach
// into each other. Everything /proc-sourced carries a proc_ name segment so it
// never collides with the CGI poe_* / port_* families.
type sshMetrics struct {
	up            prometheus.Gauge
	scrapeSeconds prometheus.Gauge
	scrapeErrors  prometheus.Counter

	// /proc/linkdown - per-port link-down reason ring.
	linkdownEvents *prometheus.GaugeVec
	linkdownReason *prometheus.GaugeVec

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
			"root shell was unreachable (or the switch was reverted to stock firmware); the CGI "+
			"metrics are unaffected."),
		scrapeSeconds: f.gauge("ssh_scrape_duration_seconds", "Duration of the last root-shell /proc poll."),
		scrapeErrors:  f.counter("ssh_scrape_errors_total", "Failed root-shell /proc polls."),

		linkdownEvents: f.vec("proc_port_linkdown_logged_events", "Number of real (non-Unknown) entries in "+
			"the RealTek driver's per-port link-down REASON ring at /proc/linkdown. The CGI "+
			"port_link_down_events is a bare count; this is evidence the ring actually recorded a reason, "+
			"and proc_port_linkdown_reason_info carries WHY.", "port"),
		linkdownReason: f.vec("proc_port_linkdown_reason_info", "Always 1. The most recent non-Unknown "+
			"link-down reason for the port, as the driver names it (e.g. SW-AdminDown, LinkFault), carried "+
			"as a label. 'none' when the ring holds no real reason.", "port", "reason"),

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
	p.m.up.Set(1)
}

// batch is the ENTIRE set of commands this collector will ever run. Every line
// is a passive read. See the safety note at the top of the file before adding.
const sshBatch = `echo @@POE; cat /proc/poe 2>/dev/null; ` +
	`echo @@LINKDOWN; cat /proc/linkdown 2>/dev/null; ` +
	`echo @@OPTICAL; cat /proc/optical 2>/dev/null; ` +
	`echo @@VLAN; cat /proc/vlan 2>/dev/null; ` +
	`echo @@DONE`

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

	var (
		port     string
		inLog    bool
		count    int
		lastReas string
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
		reason, ok := parseReasonEntry(trimmed)
		if !ok {
			continue
		}
		count++
		if lastReas == "" {
			lastReas = reason // entries are newest-first, so the first real one wins
		}
	}
	flush()
}

// parseReasonEntry returns the reason text of a link-down ring entry, and false
// if the entry is an empty slot (timestamp 0 / "Unknown").
func parseReasonEntry(s string) (string, bool) {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return "", false
	}
	// fields[0] is the timestamp; 0.000000000 marks an empty slot.
	if strings.HasPrefix(fields[0], "0.000000000") {
		return "", false
	}
	// The rest is "(code)Reason" possibly with spaces in the reason.
	rest := strings.TrimSpace(strings.Join(fields[1:], " "))
	if i := strings.Index(rest, ")"); i >= 0 && strings.HasPrefix(rest, "(") {
		rest = rest[i+1:]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" || strings.EqualFold(rest, "Unknown") {
		return "", false
	}
	return rest, true
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
