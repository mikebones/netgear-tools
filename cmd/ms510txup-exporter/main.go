// Prometheus exporter for the NETGEAR MS510TXUP PoE switch.
//
// WHY THIS ONE MATTERS MOST OF THE THREE. Every cluster node hangs off this
// switch - the four Pis on ports 1-4 and hme-srv-01 on port 10 - so it is the
// only device that can see per-port errors and link flaps for the machines
// that actually matter. The router exporter watches the edge and the XS508TM
// exporter watches a switch carrying a workstation, the router and one uplink.
// This is the one that was missing.
//
// It exists because a port was found flapping ~96 times in a week purely by
// reading syslog by hand. That should have been a graph.
//
// Read-only: only get.cgi commands, never set.cgi. A metrics collector has no
// business mutating a switch.
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

type factory struct{ reg prometheus.Registerer }

func (f factory) gauge(n, h string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "ms510txup_" + n, Help: h})
	f.reg.MustRegister(g)
	return g
}

func (f factory) counter(n, h string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "ms510txup_" + n, Help: h})
	f.reg.MustRegister(c)
	return c
}

func (f factory) vec(n, h string, labels ...string) *prometheus.GaugeVec {
	v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "ms510txup_" + n, Help: h}, labels)
	f.reg.MustRegister(v)
	return v
}

type metrics struct {
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

	igmpGlobal *prometheus.GaugeVec
	igmpVLAN   *prometheus.GaugeVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	f := factory{reg}
	return &metrics{
		up: f.gauge("up", "1 if the last poll of the switch succeeded. An exporter that cannot log in "+
			"looks exactly like a quiet network otherwise, which is how a rotated password goes unnoticed."),
		scrapeErrs: f.counter("scrape_errors_total", "Polls that failed."),
		scrapeDur:  f.gauge("scrape_duration_seconds", "Duration of the last poll."),
		lastScrape: f.gauge("last_scrape_timestamp_seconds", "Unix time of the last successful poll."),
		info:       f.vec("info", "Switch identity. Always 1.", "sysname", "serial", "uptime_days"),
		uptimeDays: f.gauge("uptime_days", "Switch uptime in days, as the device reports it."),

		portAdminUp: f.vec("port_admin_up", "1 if the port is administratively enabled.", "port"),
		portLinkUp:  f.vec("port_link_up", "1 if the port has link.", "port"),
		portSpeedMbps: f.vec("port_speed_mbps", "Negotiated link speed in Mbit/s, parsed from phyStats. "+
			"This is the NEGOTIATED result, not the configured setting, which is almost always 'Auto' "+
			"and therefore tells you nothing.", "port"),
		portFullDup:  f.vec("port_full_duplex", "1 if the negotiated link is full duplex.", "port"),
		portMaxFrame: f.vec("port_max_frame_bytes", "Configured maximum frame size.", "port"),
		portFlowCtrl: f.vec("port_flow_control_enabled", "1 if 802.3x flow control is on.", "port"),

		rxGood:  f.vec("port_rx_packets", "Good packets received since the counters were last reset.", "port"),
		rxErr:   f.vec("port_rx_errors", "Receive errors since the counters were last reset.", "port"),
		rxBroad: f.vec("port_rx_broadcast_packets", "Broadcast packets received.", "port"),
		txGood:  f.vec("port_tx_packets", "Good packets transmitted.", "port"),
		txErr:   f.vec("port_tx_errors", "Transmit errors.", "port"),
		collisions: f.vec("port_collisions", "Collisions. Non-zero on a modern full-duplex link means a "+
			"duplex mismatch, not congestion.", "port"),
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
	}
}

// --- parsing ----------------------------------------------------------------

var speedRe = regexp.MustCompile(`(\d+)\s*([MG])bps`)

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

type poller struct {
	c  *ms510txup.Client
	m  *metrics
	mu sync.Mutex
}

func (p *poller) poll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	start := time.Now()

	var failed bool
	fail := func(what string, err error) {
		log.Printf("poll: %s: %v", what, err)
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
			p.m.portFlowCtrl.WithLabelValues(port).Set(b2f(pc.FlowCtrl == 1))
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

	p.m.scrapeDur.Set(time.Since(start).Seconds())
	if failed {
		p.m.scrapeErrs.Inc()
		p.m.up.Set(0)
		return
	}
	p.m.up.Set(1)
	p.m.lastScrape.Set(float64(time.Now().Unix()))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		listen   = flag.String("listen", ":9814", "Address to serve /metrics on.")
		endpoint = flag.String("endpoint", envOr("MS510TXUP_ENDPOINT", "http://192.168.1.2"), "Switch base URL.")
		interval = flag.Duration("interval", 60*time.Second, "Poll interval. Not below 15s.")
		insecure = flag.Bool("insecure", true, "Skip TLS verification.")
	)
	flag.Parse()

	password := os.Getenv("MS510TXUP_PASSWORD")
	if password == "" {
		log.Fatal("MS510TXUP_PASSWORD is required")
	}
	// The switch's management plane is a small embedded web server that has
	// been seen returning 502 under concurrent load, and its session table is
	// finite. Polling it hard buys nothing: link state and packet counters do
	// not move meaningfully faster than this.
	if *interval < 15*time.Second {
		log.Printf("interval %s is below the 15s floor; using 15s", *interval)
		*interval = 15 * time.Second
	}

	client, err := ms510txup.NewClient(*endpoint, password, *insecure)
	if err != nil {
		log.Fatalf("client: %v", err)
	}

	reg := prometheus.NewRegistry()
	p := &poller{c: client, m: newMetrics(reg)}
	p.poll()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	// Serves a cached snapshot, so /healthz means "the process is up", not
	// "the switch answered". Switch reachability is ms510txup_up, which is a
	// metric precisely so it can be alerted on rather than restarting the pod.
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
			// Release the session rather than leaking it: this switch has a
			// finite session table and starts refusing logins once it fills.
			if err := client.Logout(); err != nil {
				log.Printf("logout: %v", err)
			}
			fmt.Println("shutdown")
			return
		}
	}
}
