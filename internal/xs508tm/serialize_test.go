package xs508tm

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockSwitch stands in for the switch's REST auth flow. It proves the client's
// serialization and per-call session release under concurrency; it does not
// validate request contents.
type mockSwitch struct {
	srv *httptest.Server

	inflight    int32
	maxInflight int32
	logins      int32
	logouts     int32
}

func newMockSwitch(t *testing.T) *mockSwitch {
	t.Helper()
	m := &mockSwitch{}
	mux := http.NewServeMux()
	handler := func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&m.inflight, 1)
		for {
			old := atomic.LoadInt32(&m.maxInflight)
			if n <= old || atomic.CompareAndSwapInt32(&m.maxInflight, old, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		defer atomic.AddInt32(&m.inflight, -1)

		switch {
		case r.URL.Path == "/api/v1/login":
			atomic.AddInt32(&m.logins, 1)
			_, _ = w.Write([]byte(`{"resp":{"status":"success"},"login":{"token":"tok-1"}}`))
		case r.URL.Path == "/api/v1/logout":
			atomic.AddInt32(&m.logouts, 1)
			_, _ = w.Write([]byte(`{}`))
		case strings.HasPrefix(r.URL.Path, "/api/v1/"):
			_, _ = w.Write([]byte(`{"name":"sw","model":"XS508TM"}`))
		default: // prime GET /
			_, _ = w.Write([]byte("{}"))
		}
	}
	mux.HandleFunc("/", handler)
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// TestConcurrentGetsSerialize proves the XS508TM client is safe under
// Terraform-style parallelism: concurrent reads never overlap at the switch, and
// each call logs in and back out so a killed run leaves no session behind in the
// small session table. Run with -race to also catch unsynchronised token access.
func TestConcurrentGetsSerialize(t *testing.T) {
	m := newMockSwitch(t)
	c, err := NewClient(m.srv.URL, "admin", "password", true)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	const n = 6
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = c.GetSystemInformation()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("GetSystemInformation #%d: %v", i, err)
		}
	}

	if got := atomic.LoadInt32(&m.maxInflight); got != 1 {
		t.Errorf("saw %d requests in flight at once; the client must serialize to 1", got)
	}
	if got := atomic.LoadInt32(&m.logins); got != n {
		t.Errorf("logged in %d times; expected one per call (%d)", got, n)
	}
	if got := atomic.LoadInt32(&m.logouts); got != n {
		t.Errorf("logged out %d times; expected one per call (%d) so no session is leaked", got, n)
	}
}
