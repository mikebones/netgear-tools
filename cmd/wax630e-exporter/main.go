// Prometheus exporter for the NETGEAR WAX630E access point.
//
// The AP was the last of the four appliances with no metrics at all. It is not
// on the storage path and carries no cluster traffic, so this is not about
// throughput - it is about the AP being the device most likely to drift
// quietly: it shipped with factory addressing, has been found pointing its
// syslog at the wrong host with the enable flag off, and holds settings that
// only ever get looked at when something is already wrong.
//
// WHAT THIS DELIBERATELY DOES NOT EXPORT: connected station counts. The AP's
// API is query-by-example - you send a skeleton of the reply you want and it
// fills it in - and it rejects ANY payload that does not match the firmware
// exactly, including one with an extra key (err_code 28). The station
// templates in scripts/wax630e_client.py predate a firmware upgrade and are
// now rejected, and the shape is not discoverable from js/vendor.bundle.js.
// Guessing would produce an exporter that silently reports nothing, which is
// worse than one that honestly covers less.
//
// Read-only. Every call here is a query-by-example read; nothing writes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"netgear-tools/internal/wax630e"
)

type factory struct{ reg prometheus.Registerer }

func (f factory) gauge(n, h string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "wax630e_" + n, Help: h})
	f.reg.MustRegister(g)
	return g
}

func (f factory) counter(n, h string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "wax630e_" + n, Help: h})
	f.reg.MustRegister(c)
	return c
}

func (f factory) vec(n, h string, labels ...string) *prometheus.GaugeVec {
	v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "wax630e_" + n, Help: h}, labels)
	f.reg.MustRegister(v)
	return v
}

type metrics struct {
	up         prometheus.Gauge
	scrapeErrs prometheus.Counter
	reauths    prometheus.Counter
	scrapeDur  prometheus.Gauge
	lastScrape prometheus.Gauge

	info          *prometheus.GaugeVec
	uptimeSeconds prometheus.Gauge
	lanTrafficB   prometheus.Gauge
	gatewayUp     prometheus.Gauge
	cloudManaged  prometheus.Gauge
	dhcpClient    prometheus.Gauge
	mgmtVLAN      prometheus.Gauge
	syslogEnabled prometheus.Gauge
	syslogTarget  *prometheus.GaugeVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	f := factory{reg}
	return &metrics{
		up: f.gauge("up", "1 if the last poll of the AP succeeded. An exporter that cannot log in looks "+
			"exactly like a quiet network otherwise, which is how a rotated password goes unnoticed."),
		scrapeErrs: f.counter("scrape_errors_total", "Polls that failed."),
		reauths: f.counter("session_reauth_total", "Times the AP's session was found dead and "+
			"re-established. Expect one per AP reboot. A rising count with no reboots means "+
			"sessions are being timed out or evicted - the AP caps concurrent logins, so "+
			"something else is logging in and pushing this one out."),
		scrapeDur:  f.gauge("scrape_duration_seconds", "Duration of the last poll."),
		lastScrape: f.gauge("last_scrape_timestamp_seconds", "Unix time of the last successful poll."),

		info: f.vec("info", "AP identity. Always 1.",
			"ap_name", "firmware", "mac", "ip", "country", "device_mode"),
		uptimeSeconds: f.gauge("uptime_seconds", "AP uptime. Parsed from the firmware's human string "+
			"(\"04 Days 13 Hrs 46 Mins\"), which is the only form it offers - so this has minute "+
			"granularity and will look like it jumps."),
		lanTrafficB: f.gauge("lan_traffic_bytes", "Total LAN traffic since boot. Parsed from a human "+
			"string (\"50.5 GB\"), so it carries that string's precision - three significant figures, "+
			"not a byte counter. Useful as a trend, useless as a rate()."),
		gatewayUp: f.gauge("default_gateway_reachable", "1 if the AP reports its default gateway "+
			"reachable. NOTE the firmware reports this as the WORD \"Reachable\", not \"1\" - unlike "+
			"every other status field on this device, which are \"1\"/\"0\" strings. Comparing it to "+
			"\"1\" reports a perfectly healthy gateway as unreachable, which is exactly what this "+
			"exporter did on its first run."),
		cloudManaged: f.gauge("cloud_managed", "1 if the AP is NETGEAR Insight-managed rather than "+
			"standalone; 0 if standalone. An Insight-managed AP takes configuration from NETGEAR's "+
			"cloud, which would silently override everything Terraform sets here. "+
			"Set to -1 when the firmware returns the field EMPTY, which it does for this "+
			"query-by-example template. -1 means \"the AP did not answer\", NOT \"standalone\" - "+
			"reporting 0 there would be inventing a reassuring answer the device never gave."),
		dhcpClient: f.gauge("dhcp_client_enabled", "1 if the AP takes its management address by DHCP. "+
			"Should be 0 - it was moved to a static 192.168.1.5 precisely so it could not land inside "+
			"the router's pool again."),
		mgmtVLAN: f.gauge("management_vlan_id", "Management VLAN the AP answers on."),
		syslogEnabled: f.gauge("syslog_enabled", "1 if remote syslog is enabled. This exists because the "+
			"AP was once found with a syslog server configured and the enable flag OFF - the two are "+
			"stored independently, so it looked configured while sending nothing at all."),
		syslogTarget: f.vec("syslog_target", "Configured syslog destination. Always 1; the target is in "+
			"the labels, so a silent change of collector shows up as a new series.", "host", "port"),
	}
}

// --- parsing ----------------------------------------------------------------

var (
	uptimeRe  = regexp.MustCompile(`(?i)(?:(\d+)\s*Days?)?\s*(?:(\d+)\s*Hrs?)?\s*(?:(\d+)\s*Mins?)?`)
	trafficRe = regexp.MustCompile(`(?i)^\s*([0-9.]+)\s*([KMGT]?)B\s*$`)
)

// parseUptime turns "04 Days 13 Hrs 46 Mins" into seconds.
//
// The AP offers uptime only as this string - there is no seconds field - so
// the granularity is a minute and the value steps rather than climbing.
func parseUptime(s string) (float64, bool) {
	m := uptimeRe.FindStringSubmatch(s)
	if m == nil || (m[1] == "" && m[2] == "" && m[3] == "") {
		return 0, false
	}
	atoi := func(v string) float64 {
		if v == "" {
			return 0
		}
		n, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0
		}
		return n
	}
	return atoi(m[1])*86400 + atoi(m[2])*3600 + atoi(m[3])*60, true
}

// parseTraffic turns "50.5 GB" into bytes.
//
// Decimal units, not binary: the AP is quoting GB the way a marketing page
// does, and treating it as GiB would overstate by 7%.
func parseTraffic(s string) (float64, bool) {
	m := trafficRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	n, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	switch strings.ToUpper(m[2]) {
	case "K":
		n *= 1e3
	case "M":
		n *= 1e6
	case "G":
		n *= 1e9
	case "T":
		n *= 1e12
	}
	return n, true
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func oneIf(s, want string) float64 {
	if s == want {
		return 1
	}
	return 0
}

type poller struct {
	c  *wax630e.Client
	m  *metrics
	mu sync.Mutex
}

// ensureSession re-establishes the session when the AP has dropped it.
//
// THIS IS WHAT STOPS THE EXPORTER WEDGING ACROSS AN AP REBOOT. The AP
// invalidates every session when it restarts, and a client still holding the
// old token gets HTML error pages instead of JSON from then on - so every
// metric here fails with
//
//	decode reply: invalid character '<' looking for beginning of value
//
// forever, because nothing in the normal read path ever decides to log in
// again. That happened for real: the AP was upgraded and rebooted, and this
// exporter reported nothing until it was manually restarted - losing exactly
// the window somebody would want the data for.
//
// The probe is cheap (one POST /sessionCheck) and only reconnects when the
// answer is no, so the steady-state cost is one extra request per poll. It
// also covers the ~30 seconds after a reboot in which the AP answers HTTPS
// but its API is not up yet: that reads as an invalid session, the login
// fails, and the next poll simply tries again.
func (p *poller) ensureSession() {
	if p.c.SessionValid() {
		return
	}
	if err := p.c.Reauthenticate(); err != nil {
		// Not fatal and not counted as its own failure: the reads below will
		// fail on their own and mark the scrape down. Logged because "session
		// gone AND could not get a new one" is a different situation from a
		// single read failing, and the distinction matters at 3am.
		log.Printf("poll: session lost and could not re-establish it: %v", err)
		return
	}
	log.Printf("poll: session was gone (AP reboot or timeout); logged in again")
	p.m.reauths.Inc()
}

func (p *poller) poll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	start := time.Now()
	var failed bool

	p.ensureSession()

	if di, err := p.c.GetDeviceInfo(); err != nil {
		log.Printf("poll: GetDeviceInfo: %v", err)
		failed = true
	} else {
		bs, mon := di.System.BasicSettings, di.System.Monitor
		p.m.info.Reset()
		p.m.info.WithLabelValues(bs.APName, mon.SysVersion, mon.EthernetMACAddress,
			mon.IPAddress, bs.CountryRegion, bs.DeviceMode).Set(1)
		if secs, ok := parseUptime(mon.DeviceInfo.UpTime); ok {
			p.m.uptimeSeconds.Set(secs)
		}
		// THREE FIELDS, THREE DIFFERENT CONVENTIONS. dhcpClientStatus is a
		// "1"/"0" string; defaultGatewayStatus is the WORD "Reachable"; and
		// cloudStatus comes back EMPTY for this template. Treating them
		// uniformly is how the first version of this exporter reported a
		// healthy gateway as unreachable.
		p.m.gatewayUp.Set(b2f(strings.EqualFold(strings.TrimSpace(mon.DefaultGatewayStatus), "Reachable")))
		p.m.dhcpClient.Set(oneIf(bs.DHCPClientStatus, "1"))
		if cs := strings.TrimSpace(bs.CloudStatus); cs == "" {
			p.m.cloudManaged.Set(-1) // unknown - see the help text
		} else {
			p.m.cloudManaged.Set(oneIf(cs, "1"))
		}
	}

	// LAN traffic. Its own call because adding these keys to the DeviceInfo
	// template makes the AP reject the WHOLE payload - query-by-example
	// matches exactly, so a combined request returns nothing rather than
	// partial data.
	var lan struct {
		System struct {
			Monitor struct {
				Stats struct {
					LAN struct {
						Traffic string `json:"traffic"`
					} `json:"lan"`
				} `json:"stats"`
			} `json:"monitor"`
		} `json:"system"`
	}
	if err := p.c.Call(map[string]any{"system": map[string]any{"monitor": map[string]any{
		"stats": map[string]any{"lan": map[string]any{"traffic": ""}}}}}, &lan); err != nil {
		log.Printf("poll: lan traffic: %v", err)
		failed = true
	} else if b, ok := parseTraffic(lan.System.Monitor.Stats.LAN.Traffic); ok {
		p.m.lanTrafficB.Set(b)
	}

	if n, err := p.c.GetNetwork(); err != nil {
		log.Printf("poll: GetNetwork: %v", err)
		failed = true
	} else if v, convErr := strconv.ParseFloat(n.ManagementVLANID, 64); convErr == nil {
		p.m.mgmtVLAN.Set(v)
	}

	if s, err := p.c.GetSyslog(); err != nil {
		log.Printf("poll: GetSyslog: %v", err)
		failed = true
	} else {
		p.m.syslogEnabled.Set(oneIf(s.Status, "1"))
		p.m.syslogTarget.Reset()
		p.m.syslogTarget.WithLabelValues(s.IP, s.Port).Set(1)
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

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		listen   = flag.String("listen", ":9815", "Address to serve /metrics on.")
		endpoint = flag.String("endpoint", envOr("WAX630E_ENDPOINT", "https://192.168.1.5"), "AP base URL.")
		username = flag.String("username", envOr("WAX630E_USERNAME", "admin"), "AP username.")
		interval = flag.Duration("interval", 120*time.Second, "Poll interval. Not below 30s.")
		insecure = flag.Bool("insecure", true, "Skip TLS verification (the AP serves a self-signed cert).")
	)
	flag.Parse()

	password := os.Getenv("WAX630E_PASSWORD")
	if password == "" {
		log.Fatal("WAX630E_PASSWORD is required")
	}
	// A HIGHER FLOOR THAN THE SWITCHES, on purpose. This AP has a small
	// session table and a FAILED login leaks a slot - once it fills, the AP
	// answers 401 to everyone including the browser. Nothing here changes
	// faster than two minutes, so there is nothing to buy by polling harder.
	if *interval < 30*time.Second {
		log.Printf("interval %s is below the 30s floor; using 30s", *interval)
		*interval = 30 * time.Second
	}

	client, err := wax630e.NewClient(*endpoint, *username, password, *insecure)
	if err != nil {
		log.Fatalf("client: %v", err)
	}
	// Hold the session between polls rather than logging in each time, for the
	// same reason as the floor above: every login cycle is a session slot.
	client.SetKeepAlive(true)

	reg := prometheus.NewRegistry()
	p := &poller{c: client, m: newMetrics(reg)}
	p.poll()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	// Serves a cached snapshot, so /healthz means "the process is up", not
	// "the AP answered". AP reachability is the wax630e_up METRIC, so it can
	// be alerted on instead of restarting the pod - which would log in again
	// and burn another session slot every time.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("polling %s every %s; serving metrics on %s", *endpoint, *interval, *listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	for {
		select {
		case <-ticker.C:
			p.poll()
		case <-stop:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = srv.Shutdown(ctx)
			cancel()
			// Releasing the session matters more here than on the switches:
			// a leaked slot on this AP eventually locks out the web UI.
			if err := client.Logout(); err != nil {
				log.Printf("logout: %v", err)
			}
			fmt.Println("shutdown")
			return
		}
	}
}
