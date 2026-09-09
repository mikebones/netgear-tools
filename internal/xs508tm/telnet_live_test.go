package xs508tm

// Live transport check against a real XS508TM root telnet shell. Gated on
// XS508_LIVE=1 so `go test ./...` stays offline. It writes ONLY to /tmp (never
// the production cert paths) and asserts base64 round-trip integrity plus exit
// code propagation.
//
//	XS508_LIVE=1 XS508_ADDR=host:2323 XS508_TELNET_PW=... go test ./internal/xs508tm -run TestTelnetLive -v

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"
)

func TestTelnetLive(t *testing.T) {
	if os.Getenv("XS508_LIVE") != "1" {
		t.Skip("set XS508_LIVE=1 (and XS508_ADDR, XS508_TELNET_PW) to run")
	}
	addr := os.Getenv("XS508_ADDR")
	pw := os.Getenv("XS508_TELNET_PW")
	if addr == "" || pw == "" {
		t.Fatal("XS508_ADDR and XS508_TELNET_PW are required")
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))

	tc := &telnetConn{conn: conn}
	if err := tc.login(pw); err != nil {
		t.Fatalf("login: %v", err)
	}

	// exit-code propagation.
	if code, _, err := tc.run("true"); err != nil || code != 0 {
		t.Fatalf("true => code=%d err=%v, want 0", code, err)
	}
	if code, _, err := tc.run("false"); err != nil || code != 1 {
		t.Fatalf("false => code=%d err=%v, want 1", code, err)
	}

	// chunked base64 round-trip of a random ~6KB blob (bigger than a real cert).
	blob := make([]byte, 6000)
	_, _ = rand.Read(blob)
	path := "/tmp/co_telnet_selftest.bin"
	if err := tc.writeFile(path, blob); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Verify integrity by hashing on the device (avoids reading a huge b64 line
	// back through the shell echo). Extract the trailing 64 hex chars of the
	// openssl dgst output and compare to the local digest.
	code, out, err := tc.run("openssl dgst -sha256 '" + path + "'")
	if err != nil || code != 0 {
		t.Fatalf("device hash: code=%d err=%v", code, err)
	}
	dev := lastHex(out, 64)
	want := hex.EncodeToString(func() []byte { s := sha256.Sum256(blob); return s[:] }())
	if dev != want {
		t.Fatalf("round-trip mismatch: device %q want %q (out=%q)", dev, want, out)
	}
	_, _, _ = tc.run("rm -f '" + path + "'")
	t.Logf("telnet transport OK: exit codes + %d-byte chunked write verified (sha256=%s)", len(blob), want)
}

// lastHex returns the last n lowercased hex characters found in s.
func lastHex(s string, n int) string {
	var b []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'F' {
			c += 'a' - 'A'
		}
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			b = append(b, c)
		} else {
			b = b[:0]
		}
	}
	if len(b) < n {
		return string(b)
	}
	return string(b[len(b)-n:])
}
