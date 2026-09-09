// Prometheus exporter for the NETGEAR MS510TXUP PoE switch.
//
// WHY THIS ONE MATTERS MOST OF THE THREE. Every cluster node hangs off this
// switch - the four Pis on ports 1-4 and hme-srv-01 on port 10 - so it is the
// only device that can see per-port errors and link flaps for the machines
// that actually matter. It exists because a port was found flapping ~96 times
// in a week purely by reading syslog by hand. That should have been a graph.
//
// SSH-ONLY, ZERO WEB SESSIONS. This exporter talks to the switch ONLY over the
// dropbear root shell (:2222, ECDSA key auth), reading the RealTek RTL93xx
// /proc tree. It holds NO web/CGI session at all. That is deliberate and load-
// bearing: the switch's embedded web server has a 4-slot session table, and
// once it fills the UI (and Terraform) lock out - so an exporter that logged in
// over CGI on a timer was quietly consuming a session the owner needed. All the
// metrics now come from root /proc instead (see ssh.go), which costs nothing.
//
// The CGI path that used to live here (port config/stats, STP, EEE, IGMP,
// firmware, the CGI PoE view) has been REMOVED. What could not be recovered
// from /proc over SSH - per-port link up/speed, error/collision counters, STP
// and EEE state - was dropped rather than kept behind a web session; see the
// header of ssh.go for exactly what and why. The owner's priority is zero web
// sessions, above metric completeness.
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
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
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
	)
	flag.Parse()

	// SSH-ONLY GUARD. The exporter has no other data path: without the root
	// shell address there is nothing to poll, and we refuse to start rather
	// than come up serving an empty /metrics that looks like a healthy switch.
	if os.Getenv("MS510TXUP_SSH_ADDR") == "" {
		log.Fatal("MS510TXUP_SSH_ADDR is required: this exporter is SSH-only (no CGI/web path). " +
			"Set it to the switch's dropbear root shell, host:port, e.g. <switch-host>:2222.")
	}
	// The old CGI password is no longer used; warn loudly if it is still wired
	// up so a stale deployment env does not look like it is doing something.
	if os.Getenv("MS510TXUP_PASSWORD") != "" {
		log.Print("MS510TXUP_PASSWORD is set but IGNORED: the CGI path was removed; this exporter is SSH-only " +
			"and holds no web session. Drop the env var from the deployment.")
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
	log.Printf("root-shell /proc metrics against %s every %s (SSH-only, no web session)", sshCfg.addr, sshCfg.interval)
	sp.poll() // one synchronous poll so /metrics is populated before the first scrape
	go sp.run()

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
	fmt.Println("shutdown")
}
