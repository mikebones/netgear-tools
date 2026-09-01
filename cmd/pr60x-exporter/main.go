// Command pr60x-exporter exposes NETGEAR PR60X router telemetry to Prometheus.
//
// It deliberately does NOT poll the router on each Prometheus scrape. The
// device's backend config daemon degrades under rapid or concurrent RPC load -
// roughly fifty back-to-back reads will wedge it into returning
// "Failed to call process_configd_request" for everything until it recovers.
// A scrape-driven exporter behind two Prometheus replicas at a 15s interval
// would reproduce that within minutes.
//
// Instead a single background goroutine polls on its own schedule (default
// 60s) and /metrics serves the last good snapshot. Prometheus can then scrape
// as often as it likes at zero cost to the router, and pr60x_last_scrape_age
// _seconds tells you if the cached data has gone stale.
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

	"terraform-provider-pr60x/internal/pr60x"
)

const namespace = "pr60x"

type metrics struct {
	up             prometheus.Gauge
	scrapeDuration prometheus.Gauge
	lastScrapeTime prometheus.Gauge
	scrapeErrors   prometheus.Counter

	info           *prometheus.GaugeVec
	managementMode *prometheus.GaugeVec
	temperature    prometheus.Gauge
	fanSpeed       prometheus.Gauge
	uptime         prometheus.Gauge

	internetConnected prometheus.Gauge
	wanStatus         *prometheus.GaugeVec

	linkStatus *prometheus.GaugeVec
	linkSpeed  *prometheus.GaugeVec

	txBytes      *prometheus.GaugeVec
	rxBytes      *prometheus.GaugeVec
	txPackets    *prometheus.GaugeVec
	rxPackets    *prometheus.GaugeVec
	txErrors     *prometheus.GaugeVec
	rxErrors     *prometheus.GaugeVec
	txDrops      *prometheus.GaugeVec
	rxDrops      *prometheus.GaugeVec
	txCollisions *prometheus.GaugeVec

	pendingAlarms prometheus.Gauge
	dhcpLeases    *prometheus.GaugeVec
	portForwards  prometheus.Gauge
}

func newMetrics(reg prometheus.Registerer) *metrics {
	f := promauto(reg)
	m := &metrics{
		up: f.gauge("up", "1 if the last poll of the router succeeded."),
		scrapeDuration: f.gauge("scrape_duration_seconds",
			"How long the last poll of the router took."),
		lastScrapeTime: f.gauge("last_scrape_timestamp_seconds",
			"Unix time of the last successful poll. Subtract from time() to get staleness."),
		scrapeErrors: f.counter("scrape_errors_total",
			"Polls that failed. The router's config daemon returns HTTP 500 under load, so a few of these are normal; a rising rate is not."),

		info: f.gaugeVec("info", "Device identity. Always 1.",
			"product_id", "serial_number", "firmware_version", "region"),
		managementMode: f.gaugeVec("management_mode",
			"1 for the router's current management plane. \"insight\" means the cloud can overwrite local config.", "mode"),
		temperature: f.gauge("system_temperature_celsius", "System temperature."),
		fanSpeed:    f.gauge("fan_speed_rpm", "Chassis fan speed."),
		uptime:      f.gauge("uptime_seconds", "Seconds since boot. A reset means the router rebooted."),

		internetConnected: f.gauge("internet_connected", "1 if the router reports the WAN as connected."),
		wanStatus: f.gaugeVec("wan_interface_up",
			"1 if the named WAN interface is online.", "interface"),

		linkStatus: f.gaugeVec("port_link_up", "1 if the port has link.", "port"),
		linkSpeed:  f.gaugeVec("port_link_speed_mbps", "Negotiated port speed.", "port"),

		txBytes:      f.gaugeVec("port_tx_bytes", "Bytes transmitted on the port since boot.", "port"),
		rxBytes:      f.gaugeVec("port_rx_bytes", "Bytes received on the port since boot.", "port"),
		txPackets:    f.gaugeVec("port_tx_packets", "Packets transmitted on the port since boot.", "port"),
		rxPackets:    f.gaugeVec("port_rx_packets", "Packets received on the port since boot.", "port"),
		txErrors:     f.gaugeVec("port_tx_errors", "Transmit errors on the port since boot.", "port"),
		rxErrors:     f.gaugeVec("port_rx_errors", "Receive errors on the port since boot.", "port"),
		txDrops:      f.gaugeVec("port_tx_drops", "Transmit drops on the port since boot.", "port"),
		rxDrops:      f.gaugeVec("port_rx_drops", "Receive drops on the port since boot.", "port"),
		txCollisions: f.gaugeVec("port_tx_collisions", "Transmit collisions on the port since boot.", "port"),

		pendingAlarms: f.gauge("pending_alarms", "Unacknowledged alarms on the device."),
		dhcpLeases:    f.gaugeVec("dhcp_leases", "Active DHCP leases the ROUTER is serving, per VLAN. Non-zero here means the router owns DHCP on that segment.", "vlan"),
		portForwards:  f.gauge("port_forwarding_rules_enabled", "Enabled WAN-to-LAN forwards. Each one is an internet-facing exposure."),
	}
	return m
}

// The port counters are exposed as gauges rather than counters even though
// they only ever increase: the device resets them on reboot and gives no way
// to detect that other than uptime going backwards. Prometheus would silently
// treat a reboot as a counter reset and invent an enormous rate. Use
// `increase()` on the gauge with a `pr60x_uptime_seconds` guard instead.

type factory struct{ reg prometheus.Registerer }

func promauto(reg prometheus.Registerer) factory { return factory{reg} }

func (f factory) gauge(name, help string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help})
	f.reg.MustRegister(g)
	return g
}

func (f factory) counter(name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Namespace: namespace, Name: name, Help: help})
	f.reg.MustRegister(c)
	return c
}

func (f factory) gaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Namespace: namespace, Name: name, Help: help}, labels)
	f.reg.MustRegister(g)
	return g
}

type poller struct {
	client *pr60x.Client
	m      *metrics
	mu     sync.Mutex
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
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

	if info, err := p.client.GetDeviceInfo(); err != nil {
		fail("getDeviceInfo", err)
	} else {
		p.m.info.Reset()
		p.m.info.WithLabelValues(info.ProductID, info.SerialNumber,
			info.FirmwareVersion, info.Region).Set(1)
		p.m.temperature.Set(float64(info.SystemTemperatureCelsius))
		p.m.fanSpeed.Set(float64(info.FanSpeedRPM))
		if secs, err := strconv.ParseFloat(strings.TrimSpace(info.Uptime), 64); err == nil {
			p.m.uptime.Set(secs)
		}
	}

	if mode, err := p.client.GetManagementMode(); err != nil {
		fail("getManagementMode", err)
	} else {
		p.m.managementMode.Reset()
		p.m.managementMode.WithLabelValues(mode.Mode).Set(1)
	}

	if st, err := p.client.GetWANStatus(); err != nil {
		fail("getWANStatus", err)
	} else {
		p.m.internetConnected.Set(boolToFloat(st.Status == "connected"))
	}

	if ifaces, err := p.client.GetDualWANStatus(); err != nil {
		fail("getDualWanStatus", err)
	} else {
		p.m.wanStatus.Reset()
		for _, i := range ifaces {
			p.m.wanStatus.WithLabelValues(i.Interface).Set(boolToFloat(i.Status == "online"))
		}
	}

	if links, err := p.client.GetWiredPortLinkDetails(); err != nil {
		fail("getWiredPortLinkDetails", err)
	} else {
		p.m.linkStatus.Reset()
		p.m.linkSpeed.Reset()
		for _, l := range links {
			p.m.linkStatus.WithLabelValues(l.Name).Set(float64(l.LinkStatus))
			p.m.linkSpeed.WithLabelValues(l.Name).Set(float64(l.LinkSpeed))
		}
	}

	if stats, err := p.client.GetTrafficStatistics(); err != nil {
		fail("getTrafficStatistics", err)
	} else {
		for _, s := range stats {
			port := s.Port
			p.m.txBytes.WithLabelValues(port).Set(pr60x.ParseCounter(s.TxBytes))
			p.m.rxBytes.WithLabelValues(port).Set(pr60x.ParseCounter(s.RxBytes))
			p.m.txPackets.WithLabelValues(port).Set(pr60x.ParseCounter(s.TxPackets))
			p.m.rxPackets.WithLabelValues(port).Set(pr60x.ParseCounter(s.RxPackets))
			p.m.txErrors.WithLabelValues(port).Set(pr60x.ParseCounter(s.TxError))
			p.m.rxErrors.WithLabelValues(port).Set(pr60x.ParseCounter(s.RxError))
			p.m.txDrops.WithLabelValues(port).Set(pr60x.ParseCounter(s.TxDrop))
			p.m.rxDrops.WithLabelValues(port).Set(pr60x.ParseCounter(s.RxDrop))
			p.m.txCollisions.WithLabelValues(port).Set(pr60x.ParseCounter(s.TxCollision))
		}
	}

	if n, err := p.client.GetPendingAlarmCount(); err != nil {
		fail("getPendingAlarmCount", err)
	} else {
		p.m.pendingAlarms.Set(float64(n))
	}

	if leases, err := p.client.ListDHCPLeases(); err != nil {
		fail("getDhcpLeases", err)
	} else {
		p.m.dhcpLeases.Reset()
		for vlan, l := range leases {
			p.m.dhcpLeases.WithLabelValues(vlan).Set(float64(len(l)))
		}
	}

	if rules, err := p.client.ListPortForwardingRules(); err != nil {
		fail("getPortForwardingRules", err)
	} else {
		enabled := 0
		for _, r := range rules {
			if r.Enabled != 0 {
				enabled++
			}
		}
		p.m.portForwards.Set(float64(enabled))
	}

	p.m.scrapeDuration.Set(time.Since(start).Seconds())
	p.m.up.Set(boolToFloat(ok))
	if ok {
		p.m.lastScrapeTime.Set(float64(time.Now().Unix()))
	} else {
		p.m.scrapeErrors.Inc()
	}
}

func main() {
	var (
		listen   = flag.String("listen", ":9812", "Address to serve /metrics on.")
		endpoint = flag.String("endpoint", envOr("PR60X_ENDPOINT", "https://192.168.1.1"), "Router base URL.")
		username = flag.String("username", envOr("PR60X_USERNAME", "admin"), "Router admin username.")
		interval = flag.Duration("interval", 60*time.Second,
			"How often to poll the router. Do not set this aggressively - the device's config daemon degrades under rapid RPC load.")
		insecure = flag.Bool("insecure", true, "Skip TLS verification (the router serves a self-signed cert on a private IP).")
	)
	flag.Parse()

	password := os.Getenv("PR60X_PASSWORD")
	if password == "" {
		log.Fatal("PR60X_PASSWORD is required")
	}
	if *interval < 15*time.Second {
		log.Fatalf("interval %s is too aggressive for this device; use 15s or more", *interval)
	}

	client, err := pr60x.NewClient(*endpoint, *username, password, *insecure)
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	reg := prometheus.NewRegistry()
	p := &poller{client: client, m: newMetrics(reg)}

	go func() {
		p.poll()
		for range time.Tick(*interval) {
			p.poll()
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<html><head><title>PR60X exporter</title></head>
<body><h1>PR60X exporter</h1><p><a href="/metrics">Metrics</a></p></body></html>`))
	})

	log.Printf("polling %s every %s; serving metrics on %s", *endpoint, *interval, *listen)
	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
