// Management-plane health metrics for the XS-series switch, read over a
// root shell rather than the REST API.
//
// WHY THIS EXISTS, AND WHAT IT DELIBERATELY DOES NOT DO
// ----------------------------------------------------
// The REST API (the rest of this exporter) surfaces port counters, VLANs and
// LLDP, but nothing about the health of the management CPU that runs the box:
// its memory, its load, the resident size of the switching daemon, or how full
// the little flash partition that holds the config has become. Those are real
// "is this appliance about to fall over" signals and they are only visible
// from a shell on the device.
//
// This collector is gated entirely on XS508TM_TELNET_ADDR being set. Leave it
// unset and the exporter behaves exactly as it did before: REST only. A telnet
// failure never touches the REST metrics - it sets xs508tm_telnet_up to 0 and
// leaves the last-known gauges in place.
//
// SAFETY - READ THIS BEFORE ADDING A COMMAND
// ------------------------------------------
// This collector runs a FIXED set of passive file reads (cat /proc/*, df) and
// nothing else. It must stay that way. The switch's data plane, PHY registers,
// buffer/MMU state and on-die temperature all live behind the Broadcom SDK
// inside the switchdrvr process, reachable only through its diagnostic console
// (the /sbin/devshell helper, the /tmp/consolepipe FIFO, or the diag socket on
// 127.0.0.1:2222). Touching ANY of those from this shell was measured to wedge
// switchdrvr long enough that the platform watchdog HARD-REBOOTS the whole
// switch - observed here as a clean ~6-minute reboot loop, one reboot per diag
// interaction, with no coredump (coredump is disabled) and no crashlog, which
// is the signature of a watchdog reset rather than a process crash. A scrape
// loop doing that every interval would keep a production switch permanently
// rebooting. So: die temperature and the other ASIC metrics are intentionally
// NOT collected here. Do not add a devshell/consolepipe call to "just read the
// temp" - it will reboot the switch. If on-die temperature is ever needed, the
// safe route is to have the switch owner enable an SNMP community (the agent is
// already listening on udp/161) and read the ENTITY-SENSOR MIB over SNMP, which
// does not go anywhere near the diagnostic console.
//
// FIRMWARE DEPENDENCY
// -------------------
// Root-shell telnet on this unit exists only because it runs a modified image
// with utelnetd enabled. If the switch is ever reverted or upgraded to stock
// firmware the shell disappears and this whole collector goes dark - which is
// exactly the graceful-degradation case above: xs508tm_telnet_up drops to 0
// and the REST metrics carry on unaffected.
package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Telnet protocol bytes. We are a deliberately dumb client: refuse every
// option the server offers so no subnegotiation state is ever entered.
const (
	tnIAC  = 255
	tnDONT = 254
	tnDO   = 253
	tnWONT = 252
	tnWILL = 251
)

// telnetConfig is the connection detail, all from the environment so nothing
// device-specific is baked into a public repository.
type telnetConfig struct {
	addr     string // host:port, e.g. switch.lan:2323
	username string
	password string
	interval time.Duration
	timeout  time.Duration
}

// telnetMetrics are the management-plane gauges. They are registered on the
// same registry as the REST metrics but kept in their own struct so the two
// collectors never reach into each other.
type telnetMetrics struct {
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

	switchdrvrRSS     prometheus.Gauge
	switchdrvrPeakRSS prometheus.Gauge
	switchdrvrThreads prometheus.Gauge

	cfgSize  prometheus.Gauge
	cfgUsed  prometheus.Gauge
	cfgRatio prometheus.Gauge
}

func newTelnetMetrics(reg prometheus.Registerer) *telnetMetrics {
	f := factory{reg}
	return &telnetMetrics{
		up:            f.gauge("telnet_up", "1 if the last management-shell poll succeeded. 0 means the root shell was unreachable (or the switch was reverted to stock firmware); the REST metrics are unaffected."),
		scrapeSeconds: f.gauge("telnet_scrape_duration_seconds", "Duration of the last management-shell poll."),
		scrapeErrors:  f.counter("telnet_scrape_errors_total", "Failed management-shell polls."),

		uptimeSeconds: f.gauge("mgmt_uptime_seconds", "Uptime of the management Linux since last boot, from /proc/uptime. A reset to near zero is a switch reboot - watch this for the watchdog reboot loop that ASIC-diagnostic access provokes on this platform."),
		load1:         f.gauge("mgmt_load1", "1-minute load average of the management CPU."),
		load5:         f.gauge("mgmt_load5", "5-minute load average of the management CPU."),
		load15:        f.gauge("mgmt_load15", "15-minute load average of the management CPU."),

		memTotal:     f.gauge("mgmt_memory_total_bytes", "MemTotal of the management CPU, from /proc/meminfo."),
		memFree:      f.gauge("mgmt_memory_free_bytes", "MemFree of the management CPU."),
		memAvailable: f.gauge("mgmt_memory_available_bytes", "MemAvailable of the management CPU - the honest 'how much can actually be used' figure. A steady decline is a management-plane leak, not a data-plane problem."),
		memCached:    f.gauge("mgmt_memory_cached_bytes", "Cached memory on the management CPU."),

		switchdrvrRSS:     f.gauge("switchdrvr_resident_bytes", "Resident set size of the switchdrvr process (the Broadcom SDK / switching daemon), from /proc/<pid>/status VmRSS. This is the process the whole switch depends on; a climbing RSS is the early warning for the leak that eventually forces a reboot."),
		switchdrvrPeakRSS: f.gauge("switchdrvr_peak_resident_bytes", "Peak resident set size of switchdrvr (VmHWM)."),
		switchdrvrThreads: f.gauge("switchdrvr_threads", "Thread count of switchdrvr. A thread leak here is as bad as a memory leak."),

		cfgSize:  f.gauge("config_partition_size_bytes", "Total size of the flash partition holding the switch config (/mnt/fastpath)."),
		cfgUsed:  f.gauge("config_partition_used_bytes", "Used bytes on the config partition."),
		cfgRatio: f.gauge("config_partition_used_ratio", "Used fraction (0-1) of the config partition. If this reaches 1 the switch can no longer save configuration changes - a silent failure the web UI does not warn about."),
	}
}

// telnetPoller owns the shell-side collection. Like the REST poller it runs on
// its own timer and serves cached gauges rather than dialing per scrape.
type telnetPoller struct {
	cfg telnetConfig
	m   *telnetMetrics
	mu  sync.Mutex
}

// run drives the poll loop until the process exits.
func (p *telnetPoller) run() {
	p.poll()
	for range time.Tick(p.cfg.interval) {
		p.poll()
	}
}

// poll opens exactly ONE shell session, runs the fixed read-only batch, parses
// it and updates the gauges. One session per interval keeps the load off the
// switch's management plane, which is small and does not enjoy being hammered.
func (p *telnetPoller) poll() {
	p.mu.Lock()
	defer p.mu.Unlock()

	start := time.Now()
	out, err := p.collect()
	p.m.scrapeSeconds.Set(time.Since(start).Seconds())
	if err != nil {
		log.Printf("telnet poll: %v", err)
		p.m.up.Set(0)
		p.m.scrapeErrors.Inc()
		return
	}
	p.parse(out)
	p.m.up.Set(1)
}

// batch is the ENTIRE set of commands this collector will ever run. Every line
// is a passive read. See the safety note at the top of the file before you
// think about adding to it.
const batch = `P=$(pgrep switchdrvr 2>/dev/null | head -1); ` +
	`echo @@UPTIME; cat /proc/uptime; ` +
	`echo @@LOADAVG; cat /proc/loadavg; ` +
	`echo @@MEMINFO; cat /proc/meminfo; ` +
	`echo @@SWITCHDRVR; cat /proc/$P/status 2>/dev/null; ` +
	`echo @@DF; df -k /mnt/fastpath; ` +
	`echo @@DONE`

// collect performs the login-and-run round trip and returns the raw shell
// output between the login and the @@DONE sentinel.
func (p *telnetPoller) collect() (string, error) {
	d := net.Dialer{Timeout: p.cfg.timeout}
	conn, err := d.Dial("tcp", p.cfg.addr)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", p.cfg.addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(p.cfg.timeout))

	// login: prompt -> username
	if _, err := readUntil(conn, []string{"login:", "Login:", "username:", "User:"}); err != nil {
		return "", fmt.Errorf("waiting for login prompt: %w", err)
	}
	if err := send(conn, p.cfg.username); err != nil {
		return "", err
	}
	if _, err := readUntil(conn, []string{"assword:"}); err != nil {
		return "", fmt.Errorf("waiting for password prompt: %w", err)
	}
	if err := send(conn, p.cfg.password); err != nil {
		return "", err
	}
	// shell prompt
	if _, err := readUntil(conn, []string{"#", "$"}); err != nil {
		return "", fmt.Errorf("waiting for shell prompt: %w", err)
	}

	if err := send(conn, batch); err != nil {
		return "", err
	}
	out, err := readUntil(conn, []string{"@@DONE"})
	if err != nil {
		return "", fmt.Errorf("running metrics batch: %w", err)
	}
	// Best-effort clean logout so the little session table is not leaked.
	_ = send(conn, "exit")
	return out, nil
}

// send writes one command line, stripping any accidental IAC byte so a value
// can never be mistaken for a telnet command.
func send(conn net.Conn, line string) error {
	line = strings.ReplaceAll(line, string([]byte{tnIAC}), "")
	_, err := conn.Write([]byte(line + "\n"))
	return err
}

// readUntil reads, answering telnet option negotiation as it goes, until one of
// the sentinel substrings appears in the accumulated plain text or the deadline
// set on the connection fires.
func readUntil(conn net.Conn, sentinels []string) (string, error) {
	var plain bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			negotiate(conn, buf[:n], &plain)
			text := plain.String()
			for _, s := range sentinels {
				if strings.Contains(text, s) {
					return text, nil
				}
			}
		}
		if err != nil {
			return plain.String(), err
		}
	}
}

// negotiate splits telnet IAC sequences out of the stream, refusing every
// option (WONT to a DO, DONT to a WILL), and appends the remaining data bytes
// to plain.
func negotiate(conn net.Conn, data []byte, plain *bytes.Buffer) {
	var reply []byte
	for i := 0; i < len(data); i++ {
		b := data[i]
		if b == tnIAC && i+2 < len(data) {
			cmd, opt := data[i+1], data[i+2]
			switch cmd {
			case tnDO:
				reply = append(reply, tnIAC, tnWONT, opt)
			case tnWILL:
				reply = append(reply, tnIAC, tnDONT, opt)
			}
			i += 2
			continue
		}
		if b == tnIAC && i+1 < len(data) && data[i+1] == tnIAC {
			plain.WriteByte(tnIAC)
			i++
			continue
		}
		plain.WriteByte(b)
	}
	if len(reply) > 0 {
		_, _ = conn.Write(reply)
	}
}

// parse pulls the numbers out of the batch output. Each field is independent:
// a section that fails to parse is skipped, not fatal, so a firmware that
// renames a field costs one gauge rather than the whole scrape.
func (p *telnetPoller) parse(out string) {
	sec := splitSections(out)

	if v := firstFloat(sec["UPTIME"]); v != nil {
		p.m.uptimeSeconds.Set(*v)
	}

	if fields := strings.Fields(sec["LOADAVG"]); len(fields) >= 3 {
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

	mem := parseKV(sec["MEMINFO"]) // values in kB
	setKB(mem, "MemTotal", p.m.memTotal)
	setKB(mem, "MemFree", p.m.memFree)
	setKB(mem, "MemAvailable", p.m.memAvailable)
	setKB(mem, "Cached", p.m.memCached)

	st := parseKV(sec["SWITCHDRVR"]) // values in kB (VmRSS/VmHWM) or count (Threads)
	setKB(st, "VmRSS", p.m.switchdrvrRSS)
	setKB(st, "VmHWM", p.m.switchdrvrPeakRSS)
	if v, ok := st["Threads"]; ok {
		if n, err := strconv.ParseFloat(strings.Fields(v)[0], 64); err == nil {
			p.m.switchdrvrThreads.Set(n)
		}
	}

	p.parseDF(sec["DF"])
}

// parseDF reads the `df -k` data line: Filesystem 1K-blocks Used Available Use% Mounted.
func (p *telnetPoller) parseDF(s string) {
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] == "Filesystem" {
			continue
		}
		blocks, err1 := strconv.ParseFloat(f[1], 64)
		used, err2 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil {
			continue
		}
		size := blocks * 1024
		usedB := used * 1024
		p.m.cfgSize.Set(size)
		p.m.cfgUsed.Set(usedB)
		if size > 0 {
			p.m.cfgRatio.Set(usedB / size)
		}
		return
	}
}

// splitSections carves the output on the @@NAME markers this batch emits.
func splitSections(out string) map[string]string {
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

// parseKV parses "Key: value ..." lines (the /proc/meminfo and
// /proc/<pid>/status shape) into a map of Key -> "value ..." (unit trimmed off
// by the caller).
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

// firstFloat returns the first whitespace-separated float in s, or nil.
func firstFloat(s string) *float64 {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return nil
	}
	return &v
}
