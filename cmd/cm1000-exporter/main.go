// cm1000-exporter exposes the NETGEAR CM1000v2 cable modem's DOCSIS status as
// Prometheus metrics.
//
// This is the last unmonitored device on the network and the only one whose
// faults belong to somebody else. Nothing here is a setting to change - a
// cable modem is provisioned by the ISP - so the output is evidence, not
// control: enough to tell a support call "uncorrectable codewords went from
// zero to thousands an hour starting Tuesday" instead of "the internet feels
// slow".
//
// The single most useful series is codewords_uncorrectable_total. Correctable
// codewords are the forward error correction working as designed and run into
// the billions; uncorrectables are data genuinely lost on the coax.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"netgear-tools/internal/cm1000"
)

func main() {
	listen := flag.String("listen", ":9816", "address to serve metrics on")
	endpoint := flag.String("endpoint", "http://192.168.100.1", "modem base URL")
	username := flag.String("username", "admin", "modem admin username")
	interval := flag.Duration("interval", 5*time.Minute, "how often to poll the modem")
	flag.Parse()

	password := os.Getenv("CM1000_PASSWORD")
	if password == "" {
		log.Fatal("CM1000_PASSWORD is not set")
	}

	// Five minutes, and the floor is 60s. Nothing here moves fast: codeword
	// counters accumulate over hours and power levels drift over days. The
	// modem also serves one connection at a time, so polling it hard competes
	// with a human trying to load the same page during an outage - exactly
	// when they need it.
	if *interval < time.Minute {
		log.Printf("interval %s is below the 1m floor; using 1m", *interval)
		*interval = time.Minute
	}

	reg := prometheus.NewRegistry()
	p := &poller{
		c: cm1000.NewClient(*endpoint, *username, password),
		m: newMetrics(reg),
	}
	p.poll()
	go func() {
		t := time.NewTicker(*interval)
		defer t.Stop()
		for range t.C {
			p.poll()
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	// /healthz is "the process is up", not "the modem answered" - modem
	// reachability is the cm1000_up METRIC. Tying liveness to the modem would
	// restart this pod every time the WAN was down, which is the worst moment
	// to lose the only record of what the WAN was doing.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("polling %s every %s; serving metrics on %s", *endpoint, *interval, *listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

// --- metrics ----------------------------------------------------------------

type factory struct{ reg prometheus.Registerer }

func (f factory) gauge(n, h string) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{Name: "cm1000_" + n, Help: h})
	f.reg.MustRegister(g)
	return g
}

func (f factory) counter(n, h string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: "cm1000_" + n, Help: h})
	f.reg.MustRegister(c)
	return c
}

func (f factory) vec(n, h string, labels ...string) *prometheus.GaugeVec {
	v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "cm1000_" + n, Help: h}, labels)
	f.reg.MustRegister(v)
	return v
}

type metrics struct {
	up         prometheus.Gauge
	scrapeErrs prometheus.Counter
	scrapeDur  prometheus.Gauge
	lastScrape prometheus.Gauge

	startupOK   *prometheus.GaugeVec
	startupInfo *prometheus.GaugeVec

	locked        *prometheus.GaugeVec
	lockedCount   *prometheus.GaugeVec
	powerDBMV     *prometheus.GaugeVec
	snrDB         *prometheus.GaugeVec
	freqHz        *prometheus.GaugeVec
	unerrored     *prometheus.GaugeVec
	correctable   *prometheus.GaugeVec
	uncorrectable *prometheus.GaugeVec
}

// Channel series carry direction (downstream/upstream) and plane (qam/ofdm)
// so the four tables share one metric name each. Modulation and channel_id go
// on the locked series only - they change when the CMTS re-plans, and putting
// them on every series would churn every time series instead of one.
var chanLabels = []string{"direction", "plane", "channel"}

func newMetrics(reg prometheus.Registerer) *metrics {
	f := factory{reg}
	return &metrics{
		up: f.gauge("up", "1 if the last poll of the modem succeeded. Note this is the MODEM, not the "+
			"internet: the modem answers on 192.168.100.1 even with the coax unplugged, so a 1 here "+
			"alongside a dead WAN is a meaningful combination, not a contradiction."),
		scrapeErrs: f.counter("scrape_errors_total", "Polls that failed."),
		scrapeDur:  f.gauge("scrape_duration_seconds", "Duration of the last poll."),
		lastScrape: f.gauge("last_scrape_timestamp_seconds", "Unix time of the last successful poll."),

		startupOK: f.vec("startup_step_ok", "1 if this DOCSIS provisioning step is in a healthy state. "+
			"The steps use different words for healthy - Locked, OK, Operational, Enable - AND put it in "+
			"different columns: Acquire Downstream Channel carries the frequency in Status and 'Locked' in "+
			"Comment. Rows that report a mode rather than a state (IP Provisioning Mode) are always 1, "+
			"because they have no failing value. Raw text is on cm1000_startup_step_info.", "step"),
		startupInfo: f.vec("startup_step_info", "Always 1. Carries each provisioning step's raw status "+
			"and comment as labels.", "step", "status", "comment"),

		locked: f.vec("channel_locked", "1 if the channel is locked. An UNLOCKED channel in a bonded "+
			"group is lost throughput, not a lost connection - which is why this rarely shows up as an "+
			"outage and usually shows up as 'the internet is slow'.",
			append(append([]string{}, chanLabels...), "channel_id", "modulation")...),
		lockedCount: f.vec("channels_locked", "Number of locked channels in this group. The headline "+
			"number: watch for it dropping, not for its absolute value.", "direction", "plane"),
		powerDBMV: f.vec("channel_power_dbmv", "RF power. DOWNSTREAM wants to sit near 0 and inside "+
			"-7..+7 dBmV. UPSTREAM is the one to watch: above roughly 51 dBmV the modem is shouting to "+
			"overcome loss, and that is the usual precursor to dropouts.", chanLabels...),
		snrDB: f.vec("channel_snr_db", "Signal-to-noise / modulation error ratio, downstream only. "+
			"QAM256 needs at least 33 dB, and wants real margin above it.", chanLabels...),
		freqHz: f.vec("channel_frequency_hz", "Channel centre frequency. Exported because the CMTS can "+
			"re-plan channels, and a frequency change under a rising error count says the fault is "+
			"upstream rather than in this house.", chanLabels...),

		unerrored: f.vec("channel_codewords_unerrored_total", "Codewords received with no errors. "+
			"COUNTER, AND IT WRAPS - the QAM channels roll over near 2^32 regularly - so use rate() or "+
			"increase() and never the raw value.", chanLabels...),
		correctable: f.vec("channel_codewords_correctable_total", "Codewords the forward error correction "+
			"repaired. Expected in the millions or billions; this is FEC working, not a fault.",
			chanLabels...),
		uncorrectable: f.vec("channel_codewords_uncorrectable_total", "Codewords the FEC could NOT repair "+
			"- data actually lost on the coax. THE metric on this device. A steady climb here is a plant "+
			"fault worth an ISP call, and it is visible long before it becomes a noticeable outage.",
			chanLabels...),
	}
}

// --- polling ----------------------------------------------------------------

type poller struct {
	mu sync.Mutex
	c  *cm1000.Client
	m  *metrics
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (p *poller) poll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	start := time.Now()

	st, err := p.c.DocsisStatus()
	if err != nil {
		log.Printf("poll: DocsisStatus: %v", err)
		p.m.up.Set(0)
		p.m.scrapeErrs.Inc()
		p.m.scrapeDur.Set(time.Since(start).Seconds())
		return
	}

	p.m.startupOK.Reset()
	p.m.startupInfo.Reset()
	for name, step := range st.Startup {
		p.m.startupOK.WithLabelValues(name).Set(b2f(step.OKFor(name)))
		p.m.startupInfo.WithLabelValues(name, step.Status, step.Comment).Set(1)
	}

	p.m.locked.Reset()
	p.m.lockedCount.Reset()
	p.m.powerDBMV.Reset()
	p.m.snrDB.Reset()
	p.m.freqHz.Reset()
	p.m.unerrored.Reset()
	p.m.correctable.Reset()
	p.m.uncorrectable.Reset()

	for _, g := range []struct {
		dir, plane string
		chs        []cm1000.Channel
	}{
		{"downstream", "qam", st.DownstreamQAM},
		{"upstream", "qam", st.UpstreamQAM},
		{"downstream", "ofdm", st.DownstreamOFDM},
		{"upstream", "ofdm", st.UpstreamOFDM},
	} {
		p.m.lockedCount.WithLabelValues(g.dir, g.plane).Set(float64(cm1000.LockedCount(g.chs)))
		for _, ch := range g.chs {
			idx := strconv.Itoa(ch.Index)
			p.m.locked.WithLabelValues(g.dir, g.plane, idx,
				strconv.Itoa(ch.ChannelID), ch.Modulation).Set(b2f(ch.Locked))
			p.m.powerDBMV.WithLabelValues(g.dir, g.plane, idx).Set(ch.PowerDBMV)
			p.m.freqHz.WithLabelValues(g.dir, g.plane, idx).Set(ch.FrequencyH)
			// Downstream-only fields. Skipped rather than exported as zero on
			// upstream, so a dashboard averaging SNR does not silently drag
			// itself down with eight zeroes.
			if g.dir == "downstream" {
				p.m.snrDB.WithLabelValues(g.dir, g.plane, idx).Set(ch.SNRDB)
				p.m.unerrored.WithLabelValues(g.dir, g.plane, idx).Set(ch.Unerrored)
				p.m.correctable.WithLabelValues(g.dir, g.plane, idx).Set(ch.Correctable)
				p.m.uncorrectable.WithLabelValues(g.dir, g.plane, idx).Set(ch.Uncorrectable)
			}
		}
	}

	p.m.up.Set(1)
	p.m.scrapeDur.Set(time.Since(start).Seconds())
	p.m.lastScrape.Set(float64(time.Now().Unix()))
}
