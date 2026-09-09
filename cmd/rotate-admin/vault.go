package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrSecretNotFound is returned by vaultKV.Read when the path holds no secret.
var ErrSecretNotFound = errors.New("secret not found")

// vaultKV is a minimal HashiCorp Vault KV client — exactly the read and write
// this tool needs, without pulling in the full Vault SDK. It supports both KV
// v2 (the default, mounted at "secret") and KV v1.
type vaultKV struct {
	addr  string
	token string
	mount string
	kvV2  bool
	http  *http.Client
}

// newVaultKV builds a client from an address, token and mount. addr and token
// normally come from VAULT_ADDR / VAULT_TOKEN.
func newVaultKV(addr, token, mount string, kvV2 bool) (*vaultKV, error) {
	if addr == "" {
		return nil, fmt.Errorf("VAULT_ADDR is required")
	}
	if token == "" {
		return nil, fmt.Errorf("VAULT_TOKEN is required")
	}
	if mount == "" {
		mount = "secret"
	}
	return &vaultKV{
		addr:  strings.TrimRight(addr, "/"),
		token: token,
		mount: strings.Trim(mount, "/"),
		kvV2:  kvV2,
		http:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// url builds the API URL for a logical secret path. KV v2 injects "/data/"
// between the mount and the path; KV v1 does not.
func (v *vaultKV) url(path string) string {
	path = strings.TrimLeft(path, "/")
	if v.kvV2 {
		return fmt.Sprintf("%s/v1/%s/data/%s", v.addr, v.mount, path)
	}
	return fmt.Sprintf("%s/v1/%s/%s", v.addr, v.mount, path)
}

// Read returns every field of the secret at path as strings. Non-string values
// are rendered with fmt so the caller always gets a usable map. A missing
// secret returns ErrSecretNotFound.
func (v *vaultKV) Read(path string) (map[string]string, error) {
	req, err := http.NewRequest(http.MethodGet, v.url(path), nil)
	if err != nil {
		return nil, fmt.Errorf("build read request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)

	resp, err := v.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%q: %w", path, ErrSecretNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read %q: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// KV v2 nests the fields under data.data; KV v1 puts them directly under
	// data.
	var envelope struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("decode read response for %q: %w", path, err)
	}

	raw := envelope.Data
	if v.kvV2 {
		inner, ok := envelope.Data["data"]
		if !ok {
			return nil, fmt.Errorf("%q: %w", path, ErrSecretNotFound)
		}
		raw = nil
		if err := json.Unmarshal(inner, &raw); err != nil {
			return nil, fmt.Errorf("decode KV v2 data for %q: %w", path, err)
		}
	}
	if raw == nil {
		return nil, fmt.Errorf("%q: %w", path, ErrSecretNotFound)
	}

	out := make(map[string]string, len(raw))
	for k, rv := range raw {
		var s string
		if err := json.Unmarshal(rv, &s); err == nil {
			out[k] = s
			continue
		}
		// Non-string field: keep its JSON form so nothing is silently dropped
		// when we write the map back.
		out[k] = strings.Trim(string(rv), "\"")
	}
	return out, nil
}

// Write stores data as the complete set of fields at path. The rotator passes
// the full field set (with one field changed), so this both replaces the
// password and preserves the other fields.
func (v *vaultKV) Write(path string, data map[string]string) error {
	var payload any = data
	if v.kvV2 {
		payload = map[string]any{"data": data}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal write payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, v.url(path), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build write request: %w", err)
	}
	req.Header.Set("X-Vault-Token", v.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.http.Do(req)
	if err != nil {
		return fmt.Errorf("write %q: %w", path, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)

	// Vault returns 200 (KV v2, with metadata) or 204 (KV v1) on success.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("write %q: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return nil
}
