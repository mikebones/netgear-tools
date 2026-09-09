// Root-SSH telemetry for the WAX630E - this exporter's PRIMARY and default data
// path. It reads the AP's Linux userland over the device's key-auth root shell
// with a single session per interval: `iw dev` for radio state, `iw dev <vap>
// station dump` for the associated clients, /proc/net/dev for per-VAP traffic,
// and /proc for CPU/memory/uptime.
//
// WHY SSH IS THE DEFAULT, NOT THE HTTP API
// ----------------------------------------
// The AP's web API (client.go / the REST collector in main.go) has two real
// costs this path avoids. First, it is query-by-example and rejects ANY payload
// that does not match the running firmware exactly (err_code 28) - which is why
// the REST collector cannot even report per-client station data: the station
// templates were invalidated by a firmware upgrade and the new shape is not
// discoverable. `iw` has no such problem and gives richer per-station data than
// the API ever did. Second, the AP has a SMALL SESSION TABLE and a failed login
// LEAKS a slot; once it fills, the AP answers 401 to everyone including the
// browser. Reading over an SSH key holds ZERO web sessions, so it cannot cause
// that lockout. So SSH is the default and REST is an opt-in fallback
// (WAX630E_REST_ENABLE), mirroring the ms510txup exporter's SSH-primary idiom.
//
// WHAT SSH EXPOSES that the web API could not:
//   - iw dev              - per-VAP radio state: channel, frequency, width and
//     txpower, plus SSID and interface type.
//   - iw dev <vap> station dump - THE per-client data the REST path cannot get:
//     associated station count, per-station RSSI, tx/rx
//     bitrates, connected time and byte counters.
//   - /proc/net/dev       - per-VAP rx/tx byte and packet counters.
//   - /proc/loadavg, /proc/meminfo, /proc/uptime - management-CPU health.
//   - /sys/class/thermal  - SoC thermal zones.
//
// WHAT STAYS REST-ONLY (config the query-by-example API models directly, not
// visible from this shell without guessing) and so lives in the opt-in REST
// collector: the management-VLAN id, the remote-syslog enable/target, the
// default-gateway-reachable flag, the cloud/Insight-managed flag, and the
// DHCP-client flag. These are the AP's drift-detection posture fields.
//
// SAFETY - READ-ONLY. Every command in the batch is a passive read (cat, iw dev
// ... info / station dump). `iw ... station dump` and `iw dev info` only read;
// nothing here runs `iw ... set`, touches uci, or reconfigures a radio. A
// metrics collector has no business changing the AP; keep it that way.
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
	addr     string // host:port, e.g. ap.lan:22
	user     string
	keyPEM   []byte
	hostKey  ssh.PublicKey // nil => accept any (LAN device)
	interval time.Duration
	timeout  time.Duration
}

// sshMetrics are the root-SSH gauges - the exporter's default metric set.
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

	thermalC *prometheus.GaugeVec

	radioInfo    *prometheus.GaugeVec
	radioChannel *prometheus.GaugeVec
	radioFreq    *prometheus.GaugeVec
	radioWidth   *prometheus.GaugeVec
	radioTxpower *prometheus.GaugeVec

	stationCount     *prometheus.GaugeVec
	stationSignal    *prometheus.GaugeVec
	stationTxBitrate *prometheus.GaugeVec
	stationRxBitrate *prometheus.GaugeVec
	stationConnected *prometheus.GaugeVec
	stationRxBytes   *prometheus.GaugeVec
	stationTxBytes   *prometheus.GaugeVec
}

func newSSHMetrics(reg prometheus.Registerer) *sshMetrics {
	f := factory{reg}
	return &sshMetrics{
		up: f.gauge("ssh_up", "1 if the last root-SSH poll of the AP succeeded. 0 means the root shell was "+
			"unreachable (or the key was rejected) - and since SSH is this exporter's primary path, a 0 means no "+
			"fresh metrics unless the opt-in REST collector is also enabled. THE availability signal to alert on."),
		scrapeSeconds: f.gauge("ssh_scrape_duration_seconds", "Duration of the last root-SSH poll."),
		scrapeErrors:  f.counter("ssh_scrape_errors_total", "Failed root-SSH polls."),

		uptimeSeconds: f.gauge("proc_uptime_seconds", "Seconds since boot from /proc/uptime. A reset means the AP rebooted."),
		load1:         f.gauge("proc_load1", "1-minute load average of the AP's CPU."),
		load5:         f.gauge("proc_load5", "5-minute load average of the AP's CPU."),
		load15:        f.gauge("proc_load15", "15-minute load average of the AP's CPU."),

		memTotal:     f.gauge("proc_memory_total_bytes", "MemTotal from /proc/meminfo."),
		memFree:      f.gauge("proc_memory_free_bytes", "MemFree from /proc/meminfo."),
		memAvailable: f.gauge("proc_memory_available_bytes", "MemAvailable from /proc/meminfo - the honest usable figure. A steady decline is a leak."),
		memCached:    f.gauge("proc_memory_cached_bytes", "Cached memory from /proc/meminfo."),

		ifRxBytes: f.vec("proc_interface_rx_bytes", "Bytes received on the netdev (per-VAP or wired), from /proc/net/dev. "+
			"Since-boot counter; use rate()/increase().", "interface"),
		ifTxBytes:   f.vec("proc_interface_tx_bytes", "Bytes transmitted on the netdev, from /proc/net/dev.", "interface"),
		ifRxPackets: f.vec("proc_interface_rx_packets", "Packets received on the netdev, from /proc/net/dev.", "interface"),
		ifTxPackets: f.vec("proc_interface_tx_packets", "Packets transmitted on the netdev, from /proc/net/dev.", "interface"),

		thermalC: f.vec("thermal_temperature_celsius", "SoC thermal-zone temperature in degrees C, from /sys/class/thermal, one series per zone.", "zone"),

		radioInfo:    f.vec("radio_info", "Always 1. Per-VAP radio identity from `iw dev`: SSID and interface type as labels.", "interface", "ssid", "type"),
		radioChannel: f.vec("radio_channel", "Operating channel number of the VAP, from `iw dev`.", "interface"),
		radioFreq:    f.vec("radio_frequency_mhz", "Operating centre frequency of the VAP in MHz, from `iw dev`. Distinguishes 2.4/5/6 GHz bands the channel number alone can alias.", "interface"),
		radioWidth:   f.vec("radio_channel_width_mhz", "Channel width in MHz (20/40/80/160), from `iw dev`. A width that quietly dropped from 160 is the usual reason throughput fell off.", "interface"),
		radioTxpower: f.vec("radio_txpower_dbm", "Transmit power of the VAP in dBm, from `iw dev`. A regulatory-domain change silently caps this.", "interface"),

		stationCount: f.vec("station_count", "Number of associated stations on the VAP, counted from `iw dev <vap> station dump`. THE client-count metric the query-by-example REST API cannot provide.", "interface"),
		stationSignal: f.vec("station_signal_dbm", "Per-station RSSI in dBm (`signal`), from station dump. Closer to 0 is stronger; below about -75 is a client that will be slow and retransmitting.",
			"interface", "station"),
		stationTxBitrate: f.vec("station_tx_bitrate_mbps", "Last tx bitrate to the station in Mbit/s. A capable client stuck at a low rate is the signature of a bad RF environment or a stuck rate-control decision.", "interface", "station"),
		stationRxBitrate: f.vec("station_rx_bitrate_mbps", "Last rx bitrate from the station in Mbit/s.", "interface", "station"),
		stationConnected: f.vec("station_connected_seconds", "Seconds the station has been associated (`connected time`). A value that keeps resetting is a client that keeps roaming away and back.", "interface", "station"),
		stationRxBytes:   f.vec("station_rx_bytes", "Bytes received from the station since association.", "interface", "station"),
		stationTxBytes:   f.vec("station_tx_bytes", "Bytes transmitted to the station since association.", "interface", "station"),
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
	p.parseThermal(sec["THERMAL"])
	p.parseIWDev(sec["IWDEV"])
	p.parseStations(sec)
	p.m.up.Set(1)
}

// sshBatch is the ENTIRE set of commands this collector will ever run. Every
// line is a passive read - see the safety note at the top of the file. The
// station dumps are emitted per interface discovered by `iw dev`, each under a
// @@STA <iface> marker so the parser can attribute them.
const sshBatch = `echo @@UPTIME; cat /proc/uptime 2>/dev/null; ` +
	`echo @@LOADAVG; cat /proc/loadavg 2>/dev/null; ` +
	`echo @@MEMINFO; cat /proc/meminfo 2>/dev/null; ` +
	`echo @@NETDEV; cat /proc/net/dev 2>/dev/null; ` +
	`echo @@THERMAL; for z in /sys/class/thermal/thermal_zone*; do [ -r "$z/temp" ] && echo "$(cat $z/type 2>/dev/null) $(cat $z/temp 2>/dev/null)"; done 2>/dev/null; ` +
	`echo @@IWDEV; iw dev 2>/dev/null; ` +
	`for d in $(iw dev 2>/dev/null | sed -n 's/^[[:space:]]*Interface //p'); do echo "@@STA $d"; iw dev "$d" station dump 2>/dev/null; done; ` +
	`echo @@DONE`

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
		return "", fmt.Errorf("running iw/proc batch: %w", err)
	}
	return string(out), nil
}

// splitSSHSections carves the batch output on the @@NAME markers it emits. A
// marker line may carry an argument (e.g. "@@STA wlan0"); the whole marker
// string ("STA wlan0") becomes the section key.
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
	mem := parseKV(s)
	setKB(mem, "MemTotal", p.m.memTotal)
	setKB(mem, "MemFree", p.m.memFree)
	setKB(mem, "MemAvailable", p.m.memAvailable)
	setKB(mem, "Cached", p.m.memCached)
}

// --- /proc/net/dev ----------------------------------------------------------

func (p *sshPoller) parseNetdev(s string) {
	p.m.ifRxBytes.Reset()
	p.m.ifTxBytes.Reset()
	p.m.ifRxPackets.Reset()
	p.m.ifTxPackets.Reset()

	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		name, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		iface := strings.TrimSpace(name)
		if iface == "" || iface == "lo" {
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
		set(p.m.ifTxBytes, 8)
		set(p.m.ifTxPackets, 9)
	}
}

// --- /sys/class/thermal -----------------------------------------------------

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
		seen[zone]++
		label := zone
		if seen[zone] > 1 {
			label = fmt.Sprintf("%s_%d", zone, seen[zone])
		}
		p.m.thermalC.WithLabelValues(label).Set(milli / 1000)
	}
}

// --- iw dev -----------------------------------------------------------------
//
// `iw dev` prints a tree:
//
//	phy#0
//		Interface wlan0
//			ifindex 10
//			type AP
//			ssid HomeLab
//			channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz
//			txpower 23.00 dBm
//
// We track the current Interface and attribute the type/ssid/channel/width/
// txpower lines that follow to it.
func (p *sshPoller) parseIWDev(s string) {
	p.m.radioInfo.Reset()
	p.m.radioChannel.Reset()
	p.m.radioFreq.Reset()
	p.m.radioWidth.Reset()
	p.m.radioTxpower.Reset()

	var iface, ssid, typ string
	flush := func() {
		if iface == "" {
			return
		}
		p.m.radioInfo.WithLabelValues(iface, ssid, typ).Set(1)
	}
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "Interface "):
			flush()
			iface = strings.TrimSpace(strings.TrimPrefix(line, "Interface "))
			ssid, typ = "", ""
		case strings.HasPrefix(line, "ssid "):
			ssid = strings.TrimSpace(strings.TrimPrefix(line, "ssid "))
		case strings.HasPrefix(line, "type "):
			typ = strings.TrimSpace(strings.TrimPrefix(line, "type "))
		case strings.HasPrefix(line, "channel "):
			ch, freq, width := parseChannelLine(line)
			if iface != "" {
				if ch >= 0 {
					p.m.radioChannel.WithLabelValues(iface).Set(ch)
				}
				if freq > 0 {
					p.m.radioFreq.WithLabelValues(iface).Set(freq)
				}
				if width > 0 {
					p.m.radioWidth.WithLabelValues(iface).Set(width)
				}
			}
		case strings.HasPrefix(line, "txpower "):
			if iface != "" {
				if v, ok := firstFloat(strings.TrimPrefix(line, "txpower ")); ok {
					p.m.radioTxpower.WithLabelValues(iface).Set(v)
				}
			}
		}
	}
	flush()
}

// parseChannelLine reads "channel 36 (5180 MHz), width: 80 MHz, center1: 5210
// MHz" into channel number, frequency MHz and width MHz. Missing pieces come
// back as -1/0.
func parseChannelLine(line string) (channel, freq, width float64) {
	channel, freq, width = -1, 0, 0
	rest := strings.TrimSpace(strings.TrimPrefix(line, "channel "))
	f := strings.Fields(rest)
	if len(f) > 0 {
		if v, err := strconv.ParseFloat(f[0], 64); err == nil {
			channel = v
		}
	}
	// frequency: the token right after "(".
	if i := strings.Index(rest, "("); i >= 0 {
		after := strings.Fields(rest[i+1:])
		if len(after) > 0 {
			if v, err := strconv.ParseFloat(after[0], 64); err == nil {
				freq = v
			}
		}
	}
	// width: token after "width:".
	if i := strings.Index(rest, "width:"); i >= 0 {
		after := strings.Fields(rest[i+len("width:"):])
		if len(after) > 0 {
			if v, err := strconv.ParseFloat(after[0], 64); err == nil {
				width = v
			}
		}
	}
	return channel, freq, width
}

// --- iw dev <vap> station dump ----------------------------------------------
//
// parseStations walks every @@STA <iface> section. Each station block is:
//
//	Station aa:bb:cc:dd:ee:ff (on wlan0)
//		rx bytes:	12345
//		tx bytes:	54321
//		signal:  	-55 dBm
//		tx bitrate:	433.3 MBit/s
//		rx bitrate:	400.0 MBit/s
//		connected time:	3600 seconds
func (p *sshPoller) parseStations(sec map[string]string) {
	p.m.stationCount.Reset()
	p.m.stationSignal.Reset()
	p.m.stationTxBitrate.Reset()
	p.m.stationRxBitrate.Reset()
	p.m.stationConnected.Reset()
	p.m.stationRxBytes.Reset()
	p.m.stationTxBytes.Reset()

	for key, body := range sec {
		if !strings.HasPrefix(key, "STA ") {
			continue
		}
		iface := strings.TrimSpace(strings.TrimPrefix(key, "STA "))
		if iface == "" {
			continue
		}
		count := p.parseStationBlock(iface, body)
		p.m.stationCount.WithLabelValues(iface).Set(float64(count))
	}
}

// parseStationBlock parses one interface's station dump and returns the number
// of stations seen.
func (p *sshPoller) parseStationBlock(iface, body string) int {
	var station string
	count := 0
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Station ") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				station = f[1]
				count++
			}
			continue
		}
		if station == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		switch key {
		case "signal":
			if v, ok := firstFloat(val); ok {
				p.m.stationSignal.WithLabelValues(iface, station).Set(v)
			}
		case "tx bitrate":
			if v, ok := firstFloat(val); ok {
				p.m.stationTxBitrate.WithLabelValues(iface, station).Set(v)
			}
		case "rx bitrate":
			if v, ok := firstFloat(val); ok {
				p.m.stationRxBitrate.WithLabelValues(iface, station).Set(v)
			}
		case "connected time":
			if v, ok := firstFloat(val); ok {
				p.m.stationConnected.WithLabelValues(iface, station).Set(v)
			}
		case "rx bytes":
			if v, ok := firstFloat(val); ok {
				p.m.stationRxBytes.WithLabelValues(iface, station).Set(v)
			}
		case "tx bytes":
			if v, ok := firstFloat(val); ok {
				p.m.stationTxBytes.WithLabelValues(iface, station).Set(v)
			}
		}
	}
	return count
}

// --- shared helpers ---------------------------------------------------------

// firstFloat returns the first whitespace-separated float in s (the leading
// token, so "-55 dBm" -> -55 and "433.3 MBit/s" -> 433.3).
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
// primary path, so WAX630E_SSH_ADDR being set is the contract; the key file is
// then required.
func loadSSHConfig(interval, timeout time.Duration) (*sshConfig, error) {
	addr := os.Getenv("WAX630E_SSH_ADDR")
	if addr == "" {
		return nil, nil
	}
	keyFile := os.Getenv("WAX630E_SSH_KEY_FILE")
	if keyFile == "" {
		return nil, fmt.Errorf("WAX630E_SSH_ADDR is set but WAX630E_SSH_KEY_FILE is empty")
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", keyFile, err)
	}
	cfg := &sshConfig{
		addr:     addr,
		user:     envOr("WAX630E_SSH_USER", "root"),
		keyPEM:   keyPEM,
		interval: interval,
		timeout:  timeout,
	}
	if hk := os.Getenv("WAX630E_SSH_HOSTKEY"); hk != "" {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hk))
		if err != nil {
			return nil, fmt.Errorf("parse WAX630E_SSH_HOSTKEY: %w", err)
		}
		cfg.hostKey = pk
	}
	return cfg, nil
}
