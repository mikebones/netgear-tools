// Command cert-operator pushes cert-manager-renewed TLS certificates onto the
// homelab NETGEAR appliances by each device's own install mechanism.
//
// cert-manager already issues and renews the appliance certificates as
// Kubernetes TLS secrets (the *-tls secrets in namespace netgear-certs). This
// controller closes the last-mile gap: getting the renewed material onto a box
// that has no idea cert-manager exists. It is the in-cluster counterpart to the
// one-off shell tooling in the private manifests repo (renew-pr60x-cert.sh and
// friends).
//
// # Shape
//
// A poll loop, not an informer. A full client-go informer on the two secrets
// would be tidier, but a poll loop needs no k8s API access at all when the
// secrets are mounted as files, and "did the cert on disk change" is exactly
// what a projected secret volume already answers for us. Reconciliation is
// idempotent and compare-before-push, so a poll that finds nothing to do is
// cheap and silent, and a restart mid-renewal is harmless.
//
// Each cycle, for every managed device:
//
//  1. Read the target cert+key from the mounted TLS secret (tls.crt/tls.key).
//  2. Dial the device on :443 and read the leaf certificate it currently
//     SERVES. Compare its SHA-256 fingerprint to the target leaf.
//  3. If they match, do nothing (idempotent, quiet). If they differ, push by
//     the device's mechanism, then re-dial to confirm the new cert is live.
//
// # Public repo hygiene
//
// This binary carries NO device addresses, credentials, or hostnames. Every
// per-device value comes from the environment (endpoints, SSH host) or a
// mounted file (the TLS secrets, the switch admin password, the router root SSH
// key). The manifests in the private repo supply those; nothing sensitive is
// baked in here.
//
// # Phase 1 scope
//
// Only the two fully-automatable devices are wired up: sw2 (XS508TM, headless
// REST upload) and router (PR60X, root SSH). sw1 (MS510TXUP) and wap1 (WAX630E)
// are left as clearly-marked TODO stubs in devices.go - see the per-device
// notes there and OPERATOR-PLAN.md in the manifests repo.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
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

// metrics are named to sit alongside the existing per-device exporters, under a
// shared netgear_cert_ prefix rather than one namespaced per device: this is
// one controller managing several devices, and the device is a label.
type metrics struct {
	pushSuccess *prometheus.GaugeVec   // netgear_cert_push_success_timestamp
	notAfter    *prometheus.GaugeVec   // netgear_cert_notafter_seconds
	pushErrors  *prometheus.CounterVec // netgear_cert_push_errors_total
	served      *prometheus.GaugeVec   // netgear_cert_served_matches_target
	lastReconc  prometheus.Gauge       // netgear_cert_last_reconcile_timestamp
}

func newMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		pushSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netgear_cert_push_success_timestamp",
			Help: "Unix time of the last cert push to the device that verified live.",
		}, []string{"device"}),
		notAfter: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netgear_cert_notafter_seconds",
			Help: "notAfter of the TARGET leaf certificate (the one cert-manager issued), as Unix seconds.",
		}, []string{"device"}),
		pushErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "netgear_cert_push_errors_total",
			Help: "Failed reconciles (unreadable secret, unreachable device, failed push, or failed verify).",
		}, []string{"device"}),
		served: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "netgear_cert_served_matches_target",
			Help: "1 if the cert the device currently serves matches the target leaf, 0 if stale, absent if unknown.",
		}, []string{"device"}),
		lastReconc: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netgear_cert_last_reconcile_timestamp",
			Help: "Unix time the reconcile loop last completed a full pass.",
		}),
	}
	reg.MustRegister(m.pushSuccess, m.notAfter, m.pushErrors, m.served, m.lastReconc)
	return m
}

type operator struct {
	devices []device
	kube    *kubeClient
	certsNS string // namespace holding the cert-manager TLS secrets
	m       *metrics
}

// reconcile runs one full pass over every managed device. Errors are logged and
// counted per device; one device failing never stops the others.
func (o *operator) reconcile(ctx context.Context) {
	for i := range o.devices {
		if ctx.Err() != nil {
			return
		}
		o.reconcileOne(ctx, &o.devices[i])
	}
	o.m.lastReconc.Set(float64(time.Now().Unix()))
}

func (o *operator) reconcileOne(ctx context.Context, d *device) {
	if d.push == nil {
		// TODO stub (sw1/wap1). Nothing to do until its mechanism lands.
		return
	}

	certPEM, keyPEM, err := o.kube.tlsSecret(ctx, o.certsNS, d.secretName)
	if err != nil {
		log.Printf("%s: read target secret %s/%s: %v", d.name, o.certsNS, d.secretName, err)
		o.m.pushErrors.WithLabelValues(d.name).Inc()
		return
	}
	leaf, err := leafFromPEM(certPEM)
	if err != nil {
		log.Printf("%s: parse target cert: %v", d.name, err)
		o.m.pushErrors.WithLabelValues(d.name).Inc()
		return
	}
	o.m.notAfter.WithLabelValues(d.name).Set(float64(leaf.NotAfter.Unix()))
	targetFP := fingerprint(leaf)

	servedLeaf, err := servedCert(ctx, d.tlsAddr)
	if err != nil {
		// Cannot compare, so cannot safely decide to push. Blindly pushing to a
		// device we cannot even TLS-dial risks hammering an already-wedged box
		// (e.g. sw2 with HTTPS left off by a prior failed swap), so we record
		// the error and wait for the next cycle rather than push blind.
		log.Printf("%s: read served cert from %s: %v", d.name, d.tlsAddr, err)
		o.m.pushErrors.WithLabelValues(d.name).Inc()
		return
	}

	if fingerprint(servedLeaf) == targetFP {
		o.m.served.WithLabelValues(d.name).Set(1)
		return // current; stay quiet
	}
	o.m.served.WithLabelValues(d.name).Set(0)

	log.Printf("%s: served cert %s != target %s (notAfter %s); pushing",
		d.name, short(fingerprint(servedLeaf)), short(targetFP), leaf.NotAfter.Format(time.RFC3339))

	if err := d.push(ctx, certPEM, keyPEM); err != nil {
		log.Printf("%s: push failed: %v", d.name, err)
		o.m.pushErrors.WithLabelValues(d.name).Inc()
		return
	}

	// Confirm the device is actually serving the new cert before calling it a
	// success. A push can return nil yet the service may still be restarting
	// (lighttpd) or re-enabling HTTPS (the switch), so re-dial with a few
	// retries before deciding.
	if err := o.verify(ctx, d, targetFP); err != nil {
		log.Printf("%s: pushed but could not verify: %v", d.name, err)
		o.m.pushErrors.WithLabelValues(d.name).Inc()
		return
	}
	o.m.served.WithLabelValues(d.name).Set(1)
	o.m.pushSuccess.WithLabelValues(d.name).Set(float64(time.Now().Unix()))
	log.Printf("%s: pushed and verified serving %s", d.name, short(targetFP))
}

// verify re-dials the device until it serves the expected fingerprint or the
// attempts run out. The management web servers here take a moment to come back
// after a cert swap (lighttpd restart / HTTPS re-enable).
func (o *operator) verify(ctx context.Context, d *device, wantFP string) error {
	const attempts = 6
	var lastErr error
	for i := 0; i < attempts; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
		leaf, err := servedCert(ctx, d.tlsAddr)
		if err != nil {
			lastErr = err
			continue
		}
		if fingerprint(leaf) == wantFP {
			return nil
		}
		lastErr = fmt.Errorf("still serving %s, want %s", short(fingerprint(leaf)), short(wantFP))
	}
	return lastErr
}

// leafFromPEM returns the first CERTIFICATE block in a PEM bundle, which for a
// cert-manager tls.crt is the leaf (intermediates follow it).
func leafFromPEM(certPEM []byte) (*x509.Certificate, error) {
	for rest := certPEM; len(rest) > 0; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(blk.Bytes)
	}
	return nil, errors.New("no CERTIFICATE block found in tls.crt")
}

// fingerprint is the SHA-256 of the certificate DER, the same identity a
// fingerprint comparison in a browser or `openssl x509 -fingerprint -sha256`
// would show.
func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func short(fp string) string {
	if len(fp) <= 12 {
		return fp
	}
	return fp[:12]
}

func main() {
	interval := envDuration("POLL_INTERVAL", 15*time.Minute)
	listen := envOr("LISTEN", ":9814")
	certsNS := envOr("CERT_SECRET_NAMESPACE", "netgear-certs")

	devices, err := buildDevices()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if len(devices) == 0 {
		log.Fatal("no devices configured; set at least one device's env (see devices.go)")
	}

	kube, err := newKubeClient()
	if err != nil {
		log.Fatalf("kubernetes client: %v", err)
	}

	reg := prometheus.NewRegistry()
	op := &operator{devices: devices, kube: kube, certsNS: certsNS, m: newMetrics(reg)}

	for _, d := range devices {
		state := "managed"
		if d.push == nil {
			state = "TODO stub (not yet automatable)"
		}
		log.Printf("device %s: %s", d.name, state)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		op.reconcile(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				op.reconcile(ctx)
			}
		}
	}()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	srv := &http.Server{Addr: listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()

	log.Printf("reconciling %d device(s) every %s; serving metrics on %s", len(devices), interval, listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
