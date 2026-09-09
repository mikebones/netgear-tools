package xs508tm

// Full end-to-end check of TelnetPushCert against a real XS508TM: it writes the
// three production cert files and restarts lighttpd. Gated on XS508_PUSH_LIVE=1.
// Intended to be run with the CURRENT target cert/key (an idempotent re-install)
// so it exercises the write+reload path without changing the served identity.
//
//	XS508_PUSH_LIVE=1 XS508_ADDR=host:2323 XS508_TELNET_PW=... \
//	  XS508_CERT_FILE=cert.pem XS508_KEY_FILE=key.pem \
//	  go test ./internal/xs508tm -run TestTelnetPushLive -v

import (
	"os"
	"testing"
	"time"
)

func TestTelnetPushLive(t *testing.T) {
	if os.Getenv("XS508_PUSH_LIVE") != "1" {
		t.Skip("set XS508_PUSH_LIVE=1 (+ XS508_ADDR, XS508_TELNET_PW, XS508_CERT_FILE, XS508_KEY_FILE)")
	}
	addr, pw := os.Getenv("XS508_ADDR"), os.Getenv("XS508_TELNET_PW")
	certPEM, err := os.ReadFile(os.Getenv("XS508_CERT_FILE"))
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	keyPEM, err := os.ReadFile(os.Getenv("XS508_KEY_FILE"))
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if err := TelnetPushCert(addr, pw, certPEM, keyPEM, 60*time.Second); err != nil {
		t.Fatalf("TelnetPushCert: %v", err)
	}
	t.Log("TelnetPushCert OK: three cert files written and lighttpd restarted")
}
