package main

import "testing"

// parsePhyStats is the CGI collector's one bit of numeric parsing that has bitten
// before: a naive \d+ regex reads "2.5 Gbps" as 5000 Mbit/s. These cases pin the
// decimal-aware behaviour and the no-link path.
func TestParsePhyStats(t *testing.T) {
	cases := []struct {
		in       string
		wantMbps float64
		wantFull bool
		wantOK   bool
	}{
		{"1000 Mbps Full Duplex", 1000, true, true},
		{"100 Mbps Half Duplex", 100, false, true},
		{"2.5 Gbps Full Duplex", 2500, true, true}, // the regression: NOT 5000
		{"10 Gbps Full Duplex", 10000, true, true},
		{"1 Gbps Full", 1000, true, true},
		{"", 0, false, false},          // no link
		{"Link Down", 0, false, false}, // no speed token
		{"Auto", 0, false, false},      // configured setting, not negotiated
	}
	for _, c := range cases {
		mbps, full, ok := parsePhyStats(c.in)
		if ok != c.wantOK || mbps != c.wantMbps || full != c.wantFull {
			t.Errorf("parsePhyStats(%q) = (%v, %v, %v); want (%v, %v, %v)",
				c.in, mbps, full, ok, c.wantMbps, c.wantFull, c.wantOK)
		}
	}
}

// TestEnvBool pins the opt-in gate: only explicit truthy values enable the CGI
// collector, so an unset/blank env keeps the exporter SSH-only.
func TestEnvBool(t *testing.T) {
	const k = "MS510TXUP_TEST_ENVBOOL"
	truthy := []string{"1", "true", "TRUE", "yes", "on", " true "}
	falsy := []string{"", "0", "false", "no", "off", "enabled?"}
	for _, v := range truthy {
		t.Setenv(k, v)
		if !envBool(k) {
			t.Errorf("envBool(%q) = false; want true", v)
		}
	}
	for _, v := range falsy {
		t.Setenv(k, v)
		if envBool(k) {
			t.Errorf("envBool(%q) = true; want false", v)
		}
	}
}

// TestLoadCGIConfigDisabledByDefault is the load-bearing guarantee: with the
// enable flag unset, loadCGIConfig returns (nil, nil) so NO web session is ever
// opened, regardless of a stale endpoint/password lingering in the env.
func TestLoadCGIConfigDisabledByDefault(t *testing.T) {
	t.Setenv("MS510TXUP_ENDPOINT", "https://switch.invalid")
	t.Setenv("MS510TXUP_PASSWORD", "leftover")
	// MS510TXUP_CGI_ENABLE deliberately not set.
	cfg, err := loadCGIConfig(60_000_000_000)
	if err != nil {
		t.Fatalf("loadCGIConfig err = %v; want nil", err)
	}
	if cfg != nil {
		t.Fatalf("loadCGIConfig = %+v; want nil (collector must be off by default)", cfg)
	}
}

// TestLoadCGIConfigEnabledRequiresEndpointAndPassword checks that turning the
// collector on but forgetting its credentials fails loudly rather than silently.
func TestLoadCGIConfigEnabledRequiresEndpointAndPassword(t *testing.T) {
	t.Setenv("MS510TXUP_CGI_ENABLE", "true")
	t.Setenv("MS510TXUP_ENDPOINT", "")
	t.Setenv("MS510TXUP_PASSWORD", "")
	if _, err := loadCGIConfig(60_000_000_000); err == nil {
		t.Fatal("loadCGIConfig with no endpoint = nil err; want an error")
	}

	t.Setenv("MS510TXUP_ENDPOINT", "https://switch.invalid")
	if _, err := loadCGIConfig(60_000_000_000); err == nil {
		t.Fatal("loadCGIConfig with no password = nil err; want an error")
	}

	t.Setenv("MS510TXUP_PASSWORD", "secret")
	cfg, err := loadCGIConfig(60_000_000_000)
	if err != nil {
		t.Fatalf("loadCGIConfig fully configured err = %v; want nil", err)
	}
	if cfg == nil || cfg.endpoint != "https://switch.invalid" || cfg.password != "secret" {
		t.Fatalf("loadCGIConfig = %+v; want the configured endpoint/password", cfg)
	}
}
