package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// pushFunc installs certPEM/keyPEM onto one device by its own mechanism. A nil
// push marks a TODO stub (a device listed but not yet automatable).
type pushFunc func(ctx context.Context, certPEM, keyPEM []byte) error

// device is one managed appliance, resolved from its spec + environment.
type device struct {
	name       string   // "sw2", "router", "sw1"
	secretName string   // cert-manager TLS secret (tls.crt/tls.key) in the certs namespace
	tlsAddr    string   // host:port to dial for the cert the device currently serves
	push       pushFunc // nil => TODO stub / not enabled
}

// deviceSpec is one row of the device table. Adding a device is one entry here
// plus its configure function; everything else (reconcile loop, metrics,
// compare-before-push, verify) is generic. secretName is the cert-manager TLS
// secret that feeds the device - it drives the manifest (which secret to mount
// and grant RBAC on), and is recorded here so the table is the single source of
// truth for the device<->secret mapping.
type deviceSpec struct {
	name       string
	secretName string
	configure  func(spec deviceSpec) (*device, error)
}

// deviceSpecs is THE device table. One struct literal per appliance.
var deviceSpecs = []deviceSpec{
	{name: "sw2", secretName: "sw2-tls", configure: configureSw2},
	{name: "router", secretName: "router-tls", configure: configureRouter},
	{name: "sw1", secretName: "sw1-tls", configure: configureSw1},
	{name: "wap1", secretName: "wap1-tls", configure: configureWap1},
}

// buildDevices resolves every spec against the environment. A spec that returns
// (nil, nil) is not configured and is skipped; one that returns a device with a
// nil push is a TODO stub and is listed but inactive.
func buildDevices() ([]device, error) {
	var out []device
	for _, spec := range deviceSpecs {
		d, err := spec.configure(spec)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", spec.name, err)
		}
		if d == nil {
			log.Printf("device %s: not configured, skipping", spec.name)
			continue
		}
		out = append(out, *d)
	}
	return out, nil
}

// configureSw2 wires the XS508TM: fully headless REST upload. Enabled whenever
// SW2_ENDPOINT is set. Endpoint (an IP) comes from the environment, never baked
// in; the admin password is read from a mounted secret.
func configureSw2(spec deviceSpec) (*device, error) {
	endpoint := os.Getenv("SW2_ENDPOINT")
	if endpoint == "" {
		return nil, nil
	}
	password := readMountedSecret("SW2_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("SW2_PASSWORD (or SW2_PASSWORD_FILE) is required when SW2_ENDPOINT is set")
	}
	return &device{
		name:       spec.name,
		secretName: spec.secretName,
		tlsAddr:    envOr("SW2_TLS_ADDR", deriveAddr(endpoint)),
		push: pushXS508TM(
			endpoint,
			envOr("SW2_USERNAME", "admin"),
			password,
			envBool("SW2_INSECURE", true),
		),
	}, nil
}

// configureRouter wires the PR60X: root SSH file-write. Enabled whenever
// ROUTER_HOST is set. The root SSH key comes from a mounted secret
// (secret/netgear/pr60x-root-ssh in Vault).
func configureRouter(spec deviceSpec) (*device, error) {
	host := os.Getenv("ROUTER_HOST")
	if host == "" {
		return nil, nil
	}
	target, err := sshTargetFromEnv("ROUTER", host, "root")
	if err != nil {
		return nil, err
	}
	return &device{
		name:       spec.name,
		secretName: spec.secretName,
		tlsAddr:    envOr("ROUTER_TLS_ADDR", net.JoinHostPort(host, "443")),
		push:       pushPR60X(target),
	}, nil
}

// configureWap1 wires the WAX630E (wap1) as a root-SSH file-write target,
// modelled on the PR60X path. Enabled whenever WAP1_HOST is set. The root SSH
// key comes from a mounted secret (secret/netgear/wax630-root-ssh in Vault);
// root was obtained via the config-restore method (see the WAX630E root-cert
// runbook in the private manifests repo). The on-box install is pushWAX630E.
func configureWap1(spec deviceSpec) (*device, error) {
	host := os.Getenv("WAP1_HOST")
	if host == "" {
		return nil, nil
	}
	target, err := sshTargetFromEnv("WAP1", host, "root")
	if err != nil {
		return nil, err
	}
	return &device{
		name:       spec.name,
		secretName: spec.secretName,
		tlsAddr:    envOr("WAP1_TLS_ADDR", net.JoinHostPort(host, "443")),
		push:       pushWAX630E(target),
	}, nil
}

// configureSw1 wires the MS510TXUP as root SSH file-write, identical in SHAPE to
// the PR60X - but GATED OFF by default (SW1_ENABLED, default false) because sw1
// root is not confirmed yet (obtained separately, in progress). While disabled
// it is listed as a TODO stub; flip SW1_ENABLED=true (and provide SW1_HOST +
// the root key at secret/netgear/ms510txup-root-ssh) to activate it with one
// env change. The apply command itself is a [VERIFY] TODO - see pushMS510TXUP.
func configureSw1(spec deviceSpec) (*device, error) {
	if !envBool("SW1_ENABLED", false) {
		// Listed but inactive: nil push => TODO stub.
		return &device{name: spec.name, secretName: spec.secretName}, nil
	}
	host := os.Getenv("SW1_HOST")
	if host == "" {
		return nil, fmt.Errorf("SW1_ENABLED=true but SW1_HOST is not set")
	}
	target, err := sshTargetFromEnv("SW1", host, "root")
	if err != nil {
		return nil, err
	}
	return &device{
		name:       spec.name,
		secretName: spec.secretName,
		tlsAddr:    envOr("SW1_TLS_ADDR", net.JoinHostPort(host, "443")),
		push:       pushMS510TXUP(target),
	}, nil
}

// sshTargetFromEnv assembles an SSH target from a device's env prefix:
//
//	<PREFIX>_HOST         host (passed in; caller already read it to gate enable)
//	<PREFIX>_SSH_PORT     TCP port (default 22)
//	<PREFIX>_SSH_USER     login user (default defUser)
//	<PREFIX>_SSH_KEY      PEM private key, or <PREFIX>_SSH_KEY_FILE a mounted path
//	<PREFIX>_SSH_HOSTKEY  optional known_hosts-style pubkey to pin; else accepted
func sshTargetFromEnv(prefix, host, defUser string) (sshTarget, error) {
	keyEnv := prefix + "_SSH_KEY"
	keyPEM := readMountedSecret(keyEnv)
	if keyPEM == "" {
		return sshTarget{}, fmt.Errorf("%s (or %s_FILE) is required", keyEnv, keyEnv)
	}
	signer, err := ssh.ParsePrivateKey([]byte(keyPEM))
	if err != nil {
		return sshTarget{}, fmt.Errorf("parse %s: %w", keyEnv, err)
	}

	var hostKey ssh.PublicKey
	if line := os.Getenv(prefix + "_SSH_HOSTKEY"); line != "" {
		// Accepts a "ssh-ed25519 AAAA..." style public key (the tail of a
		// known_hosts line). Pins the connection; otherwise it is a LAN device
		// and the host key is accepted unpinned (see sshCertPush.run).
		hostKey, _, _, _, err = ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return sshTarget{}, fmt.Errorf("parse %s_SSH_HOSTKEY: %w", prefix, err)
		}
	}

	return sshTarget{
		addr:    net.JoinHostPort(host, envOr(prefix+"_SSH_PORT", "22")),
		user:    envOr(prefix+"_SSH_USER", defUser),
		signer:  signer,
		hostKey: hostKey,
	}, nil
}

// --- small helpers -----------------------------------------------------------

// readMountedSecret reads a value from a mounted file (<name>_FILE) if present,
// else from the plain env var. The file form is preferred for anything
// multi-line or genuinely secret (an SSH private key); both are supported so the
// manifest can inject whichever is convenient.
func readMountedSecret(name string) string {
	if path := os.Getenv(name + "_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("read %s_FILE (%s): %v", name, path, err)
			return ""
		}
		return strings.TrimSpace(string(b))
	}
	return os.Getenv(name)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func envBool(name string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

func envDuration(name string, def time.Duration) time.Duration {
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Printf("%s=%q is not a duration, using %s: %v", name, v, def, err)
		return def
	}
	return d
}

// deriveAddr turns a base URL (https://192.0.2.3) into a host:443 dial
// address for the served-cert check.
func deriveAddr(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return endpoint
	}
	return net.JoinHostPort(u.Hostname(), "443")
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// concatPEM joins two PEM blobs, guaranteeing a newline between them - the
// PR60X's server.pem is key THEN cert, and a missing separator merges the two
// armor lines into one.
func concatPEM(a, b []byte) []byte {
	var buf bytes.Buffer
	buf.Write(a)
	if len(a) > 0 && a[len(a)-1] != '\n' {
		buf.WriteByte('\n')
	}
	buf.Write(b)
	return buf.Bytes()
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// truncateOut renders command output for an error message: single line, capped.
func truncateOut(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
