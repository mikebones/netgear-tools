package ms510txup

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockSwitch is a minimal stand-in for the switch's login handshake and one
// read command. It exists to prove the client's serialization under concurrency,
// so it verifies nothing about the request contents beyond which endpoint was
// hit - the real handshake's correctness is covered elsewhere.
type mockSwitch struct {
	srv *httptest.Server

	sessB64 string

	inflight    int32
	maxInflight int32
	logins      int32
	logouts     int32
}

func newMockSwitch(t *testing.T) *mockSwitch {
	t.Helper()

	// A real 1024-bit key so the client's X-CSRF-XSID RSA step actually works;
	// the session blob is tabid(32) + exponent("10001") + modulus-hex.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if key.E != 65537 {
		t.Fatalf("unexpected exponent %d; the blob layout assumes 10001", key.E)
	}
	tabid := strings.Repeat("a", 32)
	blob := tabid + "10001" + fmt.Sprintf("%x", key.N)

	m := &mockSwitch{sessB64: base64.StdEncoding.EncodeToString([]byte(blob))}

	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Track how many requests are being served at once. The client holds its
		// per-device mutex across the whole login+call, so a correct client
		// never lets the server see two requests in flight, no matter how many
		// goroutines call in.
		n := atomic.AddInt32(&m.inflight, 1)
		for {
			old := atomic.LoadInt32(&m.maxInflight)
			if n <= old || atomic.CompareAndSwapInt32(&m.maxInflight, old, n) {
				break
			}
		}
		// Hold briefly so a broken (unserialized) client would overlap here.
		time.Sleep(5 * time.Millisecond)
		defer atomic.AddInt32(&m.inflight, -1)

		cmd := r.URL.Query().Get("cmd")
		switch {
		case strings.Contains(r.URL.Path, "login.html"):
			_, _ = w.Write([]byte("{}"))
		case cmd == "home_loginAuth":
			_, _ = w.Write([]byte(`{"status":"ok","authId":"auth-1"}`))
		case cmd == "home_loginStatus":
			atomic.AddInt32(&m.logins, 1)
			_, _ = w.Write([]byte(`{"data":{"status":"ok","sess":"` + m.sessB64 + `"}}`))
		case cmd == "home_logout":
			atomic.AddInt32(&m.logouts, 1)
			_, _ = w.Write([]byte(`{}`))
		default: // any get.cgi read
			_, _ = w.Write([]byte(`{"data":{"sysName":"sw1","sysSN":"SN","sysUpTimeDays":1}}`))
		}
	}
	mux.HandleFunc("/", handler)
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockSwitch) client(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(m.srv.URL, "password", true)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// hammer fires n concurrent reads and fails on the first error.
func hammer(t *testing.T, c *Client, n int) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.GetSysInfo()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("GetSysInfo #%d: %v", i, err)
		}
	}
}

// TestConcurrentGetsSerialize proves the default (session-reuse) client the
// exporter uses is safe under Terraform-style parallelism: many concurrent
// reads never overlap at the switch and share a single login. Run with -race to
// also catch any unsynchronised access to the session fields.
func TestConcurrentGetsSerialize(t *testing.T) {
	m := newMockSwitch(t)
	c := m.client(t)

	hammer(t, c, 10)

	if got := atomic.LoadInt32(&m.maxInflight); got != 1 {
		t.Errorf("saw %d requests in flight at once; the client must serialize to 1", got)
	}
	if got := atomic.LoadInt32(&m.logins); got != 1 {
		t.Errorf("session-reuse client logged in %d times; expected exactly 1 for the whole batch", got)
	}
	if got := atomic.LoadInt32(&m.logouts); got != 0 {
		t.Errorf("session-reuse client logged out %d times mid-run; it should hold its session", got)
	}
}

// TestReleasePerCallLogsOutEveryCall proves the provider's client hands its
// session back after every call - so a killed Terraform run leaves nothing in
// the four-slot table - while still never overlapping two logins.
func TestReleasePerCallLogsOutEveryCall(t *testing.T) {
	m := newMockSwitch(t)
	c := m.client(t)
	c.SetReleasePerCall(true)

	const n = 8
	hammer(t, c, n)

	if got := atomic.LoadInt32(&m.maxInflight); got != 1 {
		t.Errorf("saw %d requests in flight at once; the client must serialize to 1", got)
	}
	if got := atomic.LoadInt32(&m.logins); got != n {
		t.Errorf("per-call client logged in %d times; expected one per call (%d)", got, n)
	}
	if got := atomic.LoadInt32(&m.logouts); got != n {
		t.Errorf("per-call client logged out %d times; expected one per call (%d) so no session is leaked", got, n)
	}
}
