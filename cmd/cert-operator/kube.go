package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// kubeClient is a deliberately tiny in-cluster Kubernetes API client: enough to
// GET one Secret and no more.
//
// Why not client-go: this module is a small, PUBLIC library of hand-rolled
// device HTTP clients, and pulling in the whole client-go dependency tree to
// read two secrets would dwarf it. The in-cluster contract is stable and
// trivial - a bearer token on disk, a CA on disk, the API server in the
// environment - so we speak it directly, the same way every device client here
// speaks its device's API directly.
//
// The pod runs in the netgear-exporter namespace (to reuse the exporters' Vault
// auth), but the cert-manager TLS secrets live in netgear-certs; a pod cannot
// mount a secret from another namespace, so they are read across the namespace
// boundary through the API instead. That read is what the Role/RoleBinding on
// netgear-certs secrets in the manifest grants.
type kubeClient struct {
	host      string
	tokenPath string
	http      *http.Client
}

const (
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// newKubeClient builds the client from the standard in-cluster environment. It
// returns an error when run outside a cluster, which is the right outcome:
// there is nowhere to read the secrets from.
func newKubeClient() (*kubeClient, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := envOr("KUBERNETES_SERVICE_PORT", "443")
	if host == "" {
		return nil, fmt.Errorf("KUBERNETES_SERVICE_HOST is unset; not running in a cluster")
	}

	caPEM, err := os.ReadFile(saCAPath)
	if err != nil {
		return nil, fmt.Errorf("read service-account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("service-account CA at %s held no certificates", saCAPath)
	}

	return &kubeClient{
		host:      "https://" + net.JoinHostPort(host, port),
		tokenPath: saTokenPath,
		http: &http.Client{
			Timeout:   15 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
	}, nil
}

// secret is the sliver of the Secret object we need.
type secret struct {
	Data map[string]string `json:"data"` // values are base64-encoded
}

// tlsSecret fetches namespace/name and returns its tls.crt and tls.key,
// base64-decoded. A projected TLS secret from cert-manager always carries both.
func (k *kubeClient) tlsSecret(ctx context.Context, namespace, name string) (certPEM, keyPEM []byte, err error) {
	// Read the token fresh each call: projected service-account tokens are
	// short-lived and rotated on disk by the kubelet, so a token cached at
	// start-up would eventually be rejected with 401.
	token, err := os.ReadFile(k.tokenPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read service-account token: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", k.host, namespace, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	req.Header.Set("Accept", "application/json")

	resp, err := k.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("GET secret %s/%s: %s: %s", namespace, name, resp.Status, firstLine(body))
	}

	var s secret
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, nil, fmt.Errorf("decode secret %s/%s: %w", namespace, name, err)
	}
	certPEM, err = decodeField(s.Data, "tls.crt")
	if err != nil {
		return nil, nil, fmt.Errorf("%s/%s: %w", namespace, name, err)
	}
	keyPEM, err = decodeField(s.Data, "tls.key")
	if err != nil {
		return nil, nil, fmt.Errorf("%s/%s: %w", namespace, name, err)
	}
	return certPEM, keyPEM, nil
}

func decodeField(data map[string]string, key string) ([]byte, error) {
	v, ok := data[key]
	if !ok {
		return nil, fmt.Errorf("secret has no %q field", key)
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("decode %q: %w", key, err)
	}
	return b, nil
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
