// Package xs508tm speaks the local management API of NETGEAR's XS-series
// smart switches (XS508TM / XS516TM / XS724TM - one firmware family, the
// bundle names all three).
//
// It is a sibling of internal/pr60x. The two devices share a lighttpd front
// end and the lhttpdsid session cookie, but NOT the API underneath: the PR60X
// funnels everything through one JSON-RPC endpoint, whereas these switches
// expose a genuine REST surface at /api/v1/<resource> with 288 documented
// routes. That makes this the easier of the two to work with, not the harder.
//
// Auth, decoded from the web UI bundle (main.e8ed842d.js):
//
//	POST /api/v1/login  {"login":{"username":"admin","password":"..."}}
//	  -> a token, thereafter sent as  Authorization: Bearer <token>
//	     alongside the lhttpdsid cookie the server sets.
package xs508tm

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"time"
)

// Client is a REST client for one switch.
type Client struct {
	endpoint string
	username string
	password string

	httpClient *http.Client

	// mu serialises requests. The PR60X's config daemon collapsed under
	// concurrent load and there is no reason to assume this firmware family
	// is sturdier; a switch management plane is not built for parallel
	// traffic. Cheap insurance either way, since callers poll on an interval.
	mu       sync.Mutex
	token    string
	lastCall time.Time
}

// minInterval is the floor between two requests.
//
// Raised from 150ms after the switch's management web server started
// returning HTTP 502 under Terraform's normal request pattern. The data plane
// was never affected - switching kept working throughout - but the management
// plane is a small embedded web server and it does fall over.
const minInterval = 400 * time.Millisecond

// transientRetries is how many times a 502/503/504 is retried before giving
// up. These are not "the request was wrong", they are "the management server
// is briefly overwhelmed", and the right response is to wait rather than to
// surface a stack of HTML at the user.
const transientRetries = 4

func NewClient(endpoint, username, password string, insecure bool) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	tr := &http.Transport{}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		endpoint: endpoint,
		username: username,
		password: password,
		httpClient: &http.Client{
			Jar:       jar,
			Transport: tr,
			Timeout:   30 * time.Second,
		},
	}, nil
}

// APIError is a non-2xx reply from the switch.
type APIError struct {
	Status int
	Body   string
	Path   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s returned %d: %s", e.Path, e.Status, e.Body)
}

// isTransient reports whether an error is the management server being briefly
// unavailable rather than a bad request.
//
// Both shapes were observed on a live switch while driving it from Terraform:
// first HTTP 502 with an HTML error page, then outright connection resets once
// it was more thoroughly wedged. Neither is a client mistake and neither
// should surface to the user as a wall of XHTML.
func isTransient(err error) bool {
	if ae, ok := err.(*APIError); ok {
		return ae.Status == http.StatusBadGateway ||
			ae.Status == http.StatusServiceUnavailable ||
			ae.Status == http.StatusGatewayTimeout
	}
	// Connection reset / EOF / timeout while the embedded web server restarts.
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, s := range []string{"EOF", "connection reset", "connection refused", "timeout", "broken pipe"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// do issues one request, retrying with backoff while the management server is
// returning a transient failure.
//
// When the retries run out the error is rewrapped, because "502" on its own
// sends you looking for a bug in the request. There are two different 502s
// here and they need different responses:
//
//   - a slow 502 while the embedded web server is briefly overloaded, which is
//     what the backoff above exists for, and
//   - an immediate 502 - lighttpd answering in ~10ms because the CGI backend
//     behind it has died outright and is not coming back on its own.
//
// The second survives any amount of retrying and needs the switch's management
// plane restarted. Note that the data plane is unaffected in both cases:
// switching continues normally while the web UI is entirely unreachable, so a
// wedged management plane is not an outage and does not justify an unplanned
// reboot of a switch carrying live traffic.
func (c *Client) do(method, path string, body, out any) error {
	var err error
	backoff := 750 * time.Millisecond
	for attempt := 0; attempt <= transientRetries; attempt++ {
		err = c.doOnce(method, path, body, out)
		if err == nil || !isTransient(err) {
			return err
		}
		time.Sleep(backoff)
		backoff *= 2
	}
	return &WedgedError{Path: path, Err: err}
}

// WedgedError reports that the management plane stayed unavailable across
// every retry.
type WedgedError struct {
	Path string
	Err  error
}

func (e *WedgedError) Error() string {
	return fmt.Sprintf("%s: the switch management plane did not recover after %d retries (%v). "+
		"If it is answering immediately rather than hanging, the CGI backend behind lighttpd has died "+
		"and only a management-plane restart will clear it; the data plane is unaffected, so this can "+
		"wait for a maintenance window.", e.Path, transientRetries, e.Err)
}

func (e *WedgedError) Unwrap() error { return e.Err }

func (c *Client) doOnce(method, path string, body, out any) error {
	if since := time.Since(c.lastCall); since < minInterval {
		time.Sleep(minInterval - since)
	}

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal body for %s: %w", path, err)
		}
		rdr = bytes.NewReader(b)
	}

	url := c.endpoint + "/api/v1/" + path
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	c.lastCall = time.Now()
	if err != nil {
		return fmt.Errorf("request %s: %w", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Body: truncate(string(raw), 200), Path: path}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode %s: %w (body: %s)", path, err, truncate(string(raw), 160))
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// prime performs a GET / so the server issues its lhttpdsid cookie before
// login, mirroring what a browser does. The PR60X rejects login outright
// without this; whether this family does has not been confirmed, and doing it
// costs one request.
func (c *Client) prime() error {
	req, err := http.NewRequest(http.MethodGet, c.endpoint+"/", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("prime session: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

type loginRequest struct {
	Login struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"login"`
}

// login exchanges credentials for a bearer token. Caller must hold c.mu.
//
// The reply envelope is not fully pinned down: the UI reads `.data` off the
// axios response and hands it to a reducer. The candidate token fields below
// cover the shapes NETGEAR uses across this firmware family; run
// scripts/xs508tm_discover.py against a real switch to confirm which one this
// firmware actually returns, and trim the rest.
func (c *Client) login() error {
	c.token = ""
	if err := c.prime(); err != nil {
		return err
	}

	var req loginRequest
	req.Login.Username = c.username
	req.Login.Password = c.password

	var reply map[string]any
	if err := c.do(http.MethodPost, "login", req, &reply); err != nil {
		return fmt.Errorf("login as %q: %w", c.username, err)
	}

	if tok := findToken(reply); tok != "" {
		c.token = tok
		return nil
	}
	return fmt.Errorf("login as %q succeeded but no token field was recognised in the reply (keys: %v)",
		c.username, keysOf(reply))
}

// findToken walks the login reply for the first plausible token value. The
// field name varies across NETGEAR firmware revisions, so this looks for any
// of the known spellings at any depth rather than assuming one.
func findToken(v any) string {
	names := map[string]bool{
		"token": true, "sessionToken": true, "session": true,
		"loginToken": true, "accessToken": true, "cookieToken": true,
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if names[k] {
				if s, ok := val.(string); ok && s != "" {
					return s
				}
			}
		}
		for _, val := range t {
			if s := findToken(val); s != "" {
				return s
			}
		}
	case []any:
		for _, val := range t {
			if s := findToken(val); s != "" {
				return s
			}
		}
	}
	return ""
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Get performs an authenticated GET against one /api/v1/ resource, logging in
// first if needed and retrying once if the session has lapsed.
func (c *Client) Get(path string, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
	}
	err := c.do(http.MethodGet, path, nil, out)
	if isAuthError(err) {
		if lerr := c.login(); lerr != nil {
			return lerr
		}
		err = c.do(http.MethodGet, path, nil, out)
	}
	return err
}

// Post performs an authenticated POST. Config writes go through here.
func (c *Client) Post(path string, body, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
	}
	err := c.do(http.MethodPost, path, body, out)
	if isAuthError(err) {
		if lerr := c.login(); lerr != nil {
			return lerr
		}
		err = c.do(http.MethodPost, path, body, out)
	}
	return err
}

func isAuthError(err error) bool {
	ae, ok := err.(*APIError)
	return ok && (ae.Status == http.StatusUnauthorized || ae.Status == http.StatusForbidden)
}

// Logout releases the session. Best effort - a switch management plane has a
// small session table and leaking them eventually locks you out of the UI.
func (c *Client) Logout() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		return
	}
	_ = c.do(http.MethodPost, "logout", nil, nil)
	c.token = ""
}

// --- Routes -----------------------------------------------------------------
//
// The full 288-entry route table is in scripts/xs508tm_routes.json, extracted
// from the UI bundle. These are the ones an exporter needs; the rest are
// available through Get/Post by name without further plumbing.
const (
	RouteSystemInformation = "system_information"
	RouteDashboard         = "dashboard_cfg"
	RoutePortStatistics    = "port_stats"
	RouteSwitchStatistics  = "switch_stats"
	RouteSwitchPorts       = "switch_ports_port"
	RoutePortConfiguration = "port_configuration"
	RouteCPUStatus         = "system_cpu_status"
	RouteLLDPNeighbors     = "lldp_neighbor_info"
	RouteLLDPLocalDevice   = "lldp_local_device"
	RouteVLANConfig        = "swcfg_vlan"
	RoutePoEConfig         = "poe_cfg"
	RoutePoEPortConfig     = "poe_port_cfg"
)

// SystemInformation is deliberately loose. Field names have not been
// confirmed against a live switch yet, so callers should treat missing values
// as absent rather than as zero. Tighten this once discovery has run.
type SystemInformation struct {
	Name            string `json:"name"`
	Model           string `json:"model"`
	SerialNumber    string `json:"serialNumber"`
	FirmwareVersion string `json:"firmwareVersion"`
	MACAddress      string `json:"macAddress"`
	Uptime          string `json:"upTime"`
}

func (c *Client) GetSystemInformation() (*SystemInformation, error) {
	var out SystemInformation
	if err := c.Get(RouteSystemInformation, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRaw fetches any route as untyped JSON. Useful while the response shapes
// are still being learned, and for the discovery sweep.
func (c *Client) GetRaw(path string) (json.RawMessage, error) {
	var out json.RawMessage
	if err := c.Get(path, &out); err != nil {
		return nil, err
	}
	return out, nil
}
