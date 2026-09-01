// Package wax630e speaks the local management API of NETGEAR's WAX6-series
// access points (verified against a WAX630E on V10.1.5.1).
//
// It shares a transport with internal/pr60x - POST /socketCommunication, the
// lighttpd lhttpdsid cookie - and almost nothing else. Three things make it
// its own protocol:
//
//  1. Login is NOT in the API map the SPA builds, and it is not /login.
//     /login is customerLogin, the NETGEAR *cloud* account modal, taking
//     {email,password}. The local admin login is a plain query-by-example
//     POST to /socketCommunication carrying a `time` header instead of the
//     usual `security` one:
//
//     {"system":{"basicSettings":{"adminName":"...","adminPasswd":"..."}}}
//
//  2. The session token arrives in the `security` RESPONSE header. The web UI
//     stores btoa(token) in a non-HttpOnly `ssid` cookie and sends
//     atob(cookie) back as the `security` request header - so for a real
//     client the response header value IS the request header value and the
//     base64 round trip can be skipped entirely.
//
//  3. Reads and writes are query-by-example: POST the JSON shape you want
//     with empty values and the device fills it in. The same shape with
//     values set is the write. There is no method name anywhere.
//
// Two status codes are worth distinguishing, because they look alike and are
// not: status 100 is "not authenticated" (the UI turns it into a bounce to
// AP_login), while status 1 with err_code 28 "Invalid configuration" means
// authentication was fine and the *payload shape* was not recognised.
package wax630e

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"
)

// Client is a client for one access point.
type Client struct {
	endpoint string
	username string
	password string

	httpClient *http.Client

	// mu serialises requests, for the same reason as the router and switch
	// clients: these are small embedded management planes and they are not
	// built for concurrent traffic.
	mu       sync.Mutex
	token    string
	lastCall time.Time
}

const minInterval = 300 * time.Millisecond

// Status values the firmware returns in the `status` field.
const (
	statusOK           = 0
	statusUnauthorized = 100
)

// errCodeInvalidConfig is returned when the query-by-example shape is not one
// the firmware recognises. It is a client-side mistake, not an auth problem.
const errCodeInvalidConfig = 28

// errCodeLockedOut is returned after more than two consecutive bad passwords;
// the reply carries a `time` in minutes until login is permitted again.
const errCodeLockedOut = 26

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

// reply is the envelope every call returns.
type reply struct {
	Status int `json:"status"`
	Data   struct {
		ErrCode int     `json:"err_code"`
		ErrMesg string  `json:"err_mesg"`
		Time    float64 `json:"time"`
	} `json:"data"`
}

// APIError is a non-zero status from the access point.
type APIError struct {
	Status  int
	ErrCode int
	Message string
}

func (e *APIError) Error() string {
	switch {
	case e.Status == statusUnauthorized:
		return "not authenticated (status 100); the session has expired or was never established"
	case e.ErrCode == errCodeInvalidConfig:
		return fmt.Sprintf("the access point did not recognise the payload shape (err_code 28: %s); "+
			"query-by-example templates must match the firmware exactly", e.Message)
	case e.ErrCode == errCodeLockedOut:
		return fmt.Sprintf("login temporarily locked out after repeated failures (err_code 26: %s)", e.Message)
	default:
		return fmt.Sprintf("status %d, err_code %d: %s", e.Status, e.ErrCode, e.Message)
	}
}

// jsTime reproduces the timestamp the UI sends on the login request:
// Date.toString() 45 minutes ahead, with the trailing "(Zone Name)" stripped.
func jsTime() string {
	return time.Now().Add(45 * time.Minute).Format("Mon Jan 02 2006 15:04:05 GMT-0700")
}

// post sends one request. Callers hold c.mu.
func (c *Client) post(payload any, headers map[string]string) (http.Header, []byte, error) {
	if d := time.Until(c.lastCall.Add(minInterval)); d > 0 {
		time.Sleep(d)
	}
	defer func() { c.lastCall = time.Now() }()

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/socketCommunication", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp.Header, raw, nil
}

// login establishes a session and captures the token. Callers hold c.mu.
func (c *Client) login() error {
	// GET / first: it issues the lhttpdsid cookie, and without it the login
	// is rejected in a way that looks exactly like a bad password.
	req, err := http.NewRequest(http.MethodGet, c.endpoint+"/", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("initial GET: %w", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	hdr, raw, err := c.post(map[string]any{
		"system": map[string]any{
			"basicSettings": map[string]any{
				"adminName":   c.username,
				"adminPasswd": c.password,
			},
		},
	}, map[string]string{"time": jsTime()})
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}

	var r reply
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("decode login reply: %w (body %.200s)", err, raw)
	}
	if r.Status != statusOK {
		return &APIError{Status: r.Status, ErrCode: r.Data.ErrCode, Message: r.Data.ErrMesg}
	}
	token := hdr.Get("security")
	if token == "" {
		return fmt.Errorf("login succeeded but no security header was returned")
	}
	c.token = token
	return nil
}

// Call sends a query-by-example payload and decodes the reply into out.
//
// Passing a template with empty values reads; passing the same shape with
// values set writes. A session is established on first use and re-established
// once if the device reports status 100.
func (c *Client) Call(payload any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
	}

	raw, err := c.callOnce(payload)
	if ae, ok := err.(*APIError); ok && ae.Status == statusUnauthorized {
		// Session expired. One re-login, then one retry.
		c.token = ""
		if err := c.login(); err != nil {
			return err
		}
		raw, err = c.callOnce(payload)
	}
	if err != nil {
		return err
	}

	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (c *Client) callOnce(payload any) ([]byte, error) {
	_, raw, err := c.post(payload, map[string]string{"security": c.token})
	if err != nil {
		return nil, err
	}
	var r reply
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("decode reply: %w (body %.200s)", err, raw)
	}
	if r.Status != statusOK {
		return nil, &APIError{Status: r.Status, ErrCode: r.Data.ErrCode, Message: r.Data.ErrMesg}
	}
	return raw, nil
}

// SyslogSettings is the AP's remote logging configuration.
//
// Every field is a string in the wire format, including the numeric ones -
// the firmware rejects real JSON numbers here.
type SyslogSettings struct {
	Status string `json:"syslogStatus"`
	IP     string `json:"syslogSrvIp"`
	Port   string `json:"syslogSrvPort"`
}

type syslogEnvelope struct {
	System struct {
		LogSettings SyslogSettings `json:"logSettings"`
	} `json:"system"`
}

func syslogPayload(s SyslogSettings) map[string]any {
	return map[string]any{"system": map[string]any{"logSettings": s}}
}

func (c *Client) GetSyslog() (SyslogSettings, error) {
	var env syslogEnvelope
	err := c.Call(syslogPayload(SyslogSettings{}), &env)
	return env.System.LogSettings, err
}

func (c *Client) SetSyslog(s SyslogSettings) error {
	return c.Call(syslogPayload(s), nil)
}

// DeviceInfo is the dashboard summary, useful for an exporter and for
// confirming the AP is standalone (CloudStatus "0") rather than Insight-managed.
type DeviceInfo struct {
	System struct {
		BasicSettings struct {
			APName           string `json:"apName"`
			CountryRegion    string `json:"sysCountryRegion"`
			DHCPClientStatus string `json:"dhcpClientStatus"`
			CloudStatus      string `json:"cloudStatus"`
			DeviceMode       string `json:"deviceMode"`
		} `json:"basicSettings"`
		Monitor struct {
			EthernetMACAddress   string `json:"ethernetMacAddress"`
			SysVersion           string `json:"sysVersion"`
			DefaultGateway       string `json:"defaultGateway"`
			DefaultGatewayStatus string `json:"defaultGatewayStatus"`
			IPAddress            string `json:"ipAddress"`
			DeviceInfo           struct {
				UpTime string `json:"UpTime"`
			} `json:"DeviceInfo"`
		} `json:"monitor"`
	} `json:"system"`
}

func (c *Client) GetDeviceInfo() (DeviceInfo, error) {
	var out DeviceInfo
	err := c.Call(map[string]any{"system": map[string]any{
		"basicSettings": map[string]any{
			"apName": "", "sysCountryRegion": "", "dhcpClientStatus": "",
		},
		"monitor": map[string]any{
			"ethernetMacAddress": "", "sysVersion": "", "sysCountryRegion": "",
			"defaultGateway": "", "defaultGatewayStatus": "", "ipAddress": "",
			"DeviceInfo": map[string]any{"UpTime": ""},
		},
	}}, &out)
	return out, err
}

// Logout releases the session. The AP allows only a small number of concurrent
// sessions, so leaking them eventually locks the web UI out too.
func (c *Client) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/logout", bytes.NewReader([]byte("{}")))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("security", c.token)
	resp, err := c.httpClient.Do(req)
	if err == nil {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	c.token = ""
	return err
}
