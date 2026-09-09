// Prometheus exporter for the NETGEAR MS510TXUP PoE switch.
//
// WHY THIS ONE MATTERS MOST OF THE THREE. Every cluster node hangs off this
// switch - the four Pis on ports 1-4 and hme-srv-01 on port 10 - so it is the
// only device that can see per-port errors and link flaps for the machines
// that actually matter. It exists because a port was found flapping ~96 times
// in a week purely by reading syslog by hand. That should have been a graph.
//
// SSH-FIRST, ZERO WEB SESSIONS BY DEFAULT. This exporter's DEFAULT and primary
// data path is the dropbear root shell (:2222, ECDSA key auth), reading the
// RealTek RTL93xx /proc tree (see ssh.go). In the default configuration it
// holds NO web/CGI session at all. That is deliberate and load-bearing: the
// switch's embedded web server has a 4-slot session table, and once it fills
// the UI (and Terraform) lock out - so an exporter that logged in over CGI on a
// timer was quietly consuming a session the owner needed.
//
// OPT-IN CGI FALLBACK. The web/CGI-admin collector (cgi.go) is kept behind a
// feature flag - OFF by default - because it recovers the metrics that are NOT
// in /proc: per-port link up/speed/duplex, error/collision counters, STP state,
// and EEE/green-ethernet. Set MS510TXUP_CGI_ENABLE=true (plus MS510TXUP_ENDPOINT
// and MS510TXUP_PASSWORD) to turn it on; while up it also re-provides the port
// config/stats and PoE view as a fallback for when the root shell is down. This
// mirrors cert-operator's SSH-primary + web-fallback idiom. Enabling it costs
// exactly ONE of the four web session slots for the life of the process, which
// is why it is opt-in: leave it off (the default) and the exporter is SSH-only
// and opens zero web sessions, exactly as when the CGI path had been removed.
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
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"netgear-tools/internal/ms510txup"
)

// --- metrics helpers --------------------------------------------------------

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
		listen = flag.String("listen", ":9814", "Address to serve /metrics on.")
		// Root-shell /proc poll interval. See ssh.go; the switch has a small
		// single-core management plane, so this is not run hard.
		sshInterval = flag.Duration("ssh-interval", 60*time.Second, "Root-shell /proc poll interval. Not below 30s.")
		// CGI/web-admin collector. OPT-IN and OFF by default. See cgi.go.
		cgiInterval = flag.Duration("cgi-interval", 60*time.Second,
			"CGI/web-admin poll interval when the CGI collector is enabled. Not below 15s.")
		cgiFlag = flag.Bool("cgi", false,
			"Enable the opt-in CGI/web-admin collector (or set MS510TXUP_CGI_ENABLE=true). OFF by default. "+
				"It recovers the metrics not available over /proc (per-port link up/speed/duplex, error/collision "+
				"counters, STP state, EEE) and acts as a fallback for the port/PoE view. TRADEOFF: enabling it "+
				"consumes ONE of the switch's four web session slots for the life of the process - the SSH path is "+
				"preferred precisely because it holds zero. Requires MS510TXUP_ENDPOINT and MS510TXUP_PASSWORD.")
	)
	flag.Parse()

	// SSH-FIRST GUARD. SSH is the primary data path: without the root shell
	// address there is nothing to poll on the default path, and we refuse to
	// start rather than come up serving an empty /metrics that looks like a
	// healthy switch.
	if os.Getenv("MS510TXUP_SSH_ADDR") == "" {
		log.Fatal("MS510TXUP_SSH_ADDR is required: SSH is this exporter's primary data path. " +
			"Set it to the switch's dropbear root shell, host:port, e.g. <switch-host>:2222. " +
			"The CGI/web collector is an opt-in fallback (MS510TXUP_CGI_ENABLE=true), not a substitute.")
	}
	// MS510TXUP_CGI_ENABLE is the authority so the deployment can flip the
	// collector on from the env alone. An explicit --cgi on the command line
	// overrides the env (either direction), so both are a single source of
	// truth by the time loadCGIConfig reads the env.
	if isFlagSet("cgi") {
		if err := os.Setenv("MS510TXUP_CGI_ENABLE", strconv.FormatBool(*cgiFlag)); err != nil {
			log.Fatalf("set MS510TXUP_CGI_ENABLE: %v", err)
		}
	}

	reg := prometheus.NewRegistry()

	sshCfg, err := loadSSHConfig(*sshInterval, 15*time.Second)
	if err != nil {
		log.Fatalf("ssh collector: %v", err)
	}
	if sshCfg.interval < 30*time.Second {
		log.Fatalf("ssh interval %s is too aggressive for the switch management plane; use 30s or more", sshCfg.interval)
	}
	sp := &sshPoller{cfg: *sshCfg, m: newSSHMetrics(reg)}
	log.Printf("root-shell /proc metrics against %s every %s (SSH primary)", sshCfg.addr, sshCfg.interval)
	sp.poll() // one synchronous poll so /metrics is populated before the first scrape
	go sp.run()

	// Opt-in CGI/web-admin collector. loadCGIConfig returns (nil, nil) when
	// MS510TXUP_CGI_ENABLE is not set, so the default path opens ZERO web
	// sessions and the /tmp/sess-empty guarantee holds. When enabled it holds
	// exactly one session for the life of the process.
	var cgiClient *ms510txup.Client
	if *cgiInterval < 15*time.Second {
		log.Printf("cgi interval %s is below the 15s floor; using 15s", *cgiInterval)
		*cgiInterval = 15 * time.Second
	}
	if cgiCfg, err := loadCGIConfig(*cgiInterval); err != nil {
		log.Fatalf("cgi collector: %v", err)
	} else if cgiCfg != nil {
		client, err := ms510txup.NewClient(cgiCfg.endpoint, cgiCfg.password, cgiCfg.insecure)
		if err != nil {
			log.Fatalf("cgi client: %v", err)
		}
		cgiClient = client
		cp := &cgiPoller{c: client, m: newCGIMetrics(reg)}
		log.Printf("CGI/web-admin metrics ENABLED against %s every %s - this holds ONE of the switch's "+
			"four web session slots; the UI/Terraform share that table", cgiCfg.endpoint, cgiCfg.interval)
		cp.poll() // one synchronous poll so the CGI metrics are populated before the first scrape
		go cp.run(cgiCfg.interval)
	} else {
		log.Print("CGI/web-admin collector disabled (SSH-only, zero web sessions). " +
			"Set MS510TXUP_CGI_ENABLE=true with MS510TXUP_ENDPOINT and MS510TXUP_PASSWORD to enable it.")
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	// /healthz means "the process is up", not "the switch answered" - it serves
	// a cached snapshot. Switch reachability is the ms510txup_ssh_up METRIC,
	// deliberately, so it can be alerted on instead of restarting the pod in a
	// loop while the switch (or its root shell) is unreachable.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("serving metrics on %s", *listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = srv.Shutdown(ctx)
	cancel()
	// Release the CGI session on the way out rather than leaking it: the switch
	// has a finite session table and starts refusing logins once it fills. No-op
	// when the CGI collector was never enabled (cgiClient stays nil).
	if cgiClient != nil {
		if err := cgiClient.Logout(); err != nil {
			log.Printf("cgi logout: %v", err)
		}
	}
	fmt.Println("shutdown")
}

// isFlagSet reports whether the named flag was passed on the command line, as
// opposed to left at its default - so an explicit --cgi=false is honoured.
func isFlagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
