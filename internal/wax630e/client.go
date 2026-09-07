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
	"strings"
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

	// keepAlive holds the session open between calls. It defaults to false,
	// which means every Call logs in and out again.
	//
	// That costs two extra requests per call and is still the right default:
	// the AP has a hard cap on concurrent sessions, nothing in this package
	// gets a teardown hook from terraform-plugin-framework, and a leaked
	// session is not merely untidy - once they are gone, login returns 401 and
	// the human is locked out of the web UI until they time out. A long-lived
	// poller (an exporter) should set this true, since it owns its lifetime and
	// can log out on shutdown.
	keepAlive bool
}

// SetKeepAlive holds one session open across calls instead of logging in and
// out per call. Callers that enable it are responsible for calling Logout.
func (c *Client) SetKeepAlive(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keepAlive = v
}

const minInterval = 300 * time.Millisecond

// Status values the firmware returns in the `status` field.
const (
	statusOK           = 0
	statusUnauthorized = 100

	// statusSessionsExhausted is returned by the LOGIN call when the AP has no
	// free session slots. It holds only a handful and frees them on timeout, so
	// a client that logs in per operation and never logs out locks the web UI
	// out too. See keepAlive.
	statusSessionsExhausted = 401
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
	path := "/socketCommunication"
	if p, ok := headers["__path"]; ok {
		path = p
		delete(headers, "__path")
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint+path, bytes.NewReader(body))
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
	if r.Status == statusSessionsExhausted {
		return fmt.Errorf("the access point has no free session slots (status 401). It caps concurrent " +
			"logins and frees them only on timeout, so this usually means sessions were leaked rather " +
			"than that anything is wrong with the credentials. Wait for them to expire, or log out of " +
			"the web UI")
	}
	if r.Status != statusOK {
		return &APIError{Status: r.Status, ErrCode: r.Data.ErrCode, Message: r.Data.ErrMesg}
	}
	// WHERE THE TOKEN LIVES DEPENDS ON THE FIRMWARE.
	//
	// V10.1.5.1 returned it in the `security` RESPONSE HEADER. V10.8.10.10
	// moved it into the body as system.security_token - a SIBLING of
	// basicSettings, not inside it - and stopped sending the header. Accept
	// either, newest first.
	//
	// Getting this wrong is expensive rather than merely broken: the AP has
	// already created the session by the time the token is read, so a client
	// that errors out here holds a slot it cannot release. Repeat that a few
	// times and the AP runs out and answers 401 to everything, including the
	// browser - which is exactly what happened after this upgrade.
	var tokenBody struct {
		System struct {
			SecurityToken string `json:"security_token"`
		} `json:"system"`
	}
	_ = json.Unmarshal(raw, &tokenBody)

	token := tokenBody.System.SecurityToken
	if token == "" {
		token = hdr.Get("security")
	}
	if token == "" {
		return fmt.Errorf("login succeeded but returned no token in either the security " +
			"header or system.security_token; the session is now held on the AP and cannot be released")
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
		if !c.keepAlive {
			// Release the slot however this call turns out.
			defer c.logoutLocked()
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

// --- network addressing -----------------------------------------------------

// NetworkSettings is the AP's management addressing.
//
// Every field is a string on the wire, including the numeric ones.
//
// A WARNING THAT IS EASY TO LEARN THE HARD WAY: the static fields are
// independent of DHCPClientStatus and ship as FACTORY DEFAULTS - 192.168.0.100
// with a 192.168.0.1 gateway. Turning DHCP off without setting them in the
// same write drops the AP onto a different subnet and out of reach. Always
// send the whole struct.
type NetworkSettings struct {
	DeviceMode       string `json:"deviceMode"`
	DHCPClientStatus string `json:"dhcpClientStatus"` // "1" DHCP, "0" static
	IPAddr           string `json:"ipAddr"`
	NetmaskAddr      string `json:"netmaskAddr"`
	GatewayAddr      string `json:"gatewayAddr"`
	PrimaryDNS       string `json:"priDnsAddr"`
	SecondaryDNS     string `json:"sndDnsAddr"`
	IntegrityCheck   string `json:"networkIntegralityCheck"`
	UntaggedVLANOn   string `json:"untaggedVlanStatus"`
	UntaggedVLANID   string `json:"untaggedVlanID"`
	ManagementVLANID string `json:"managementVlanID"`
	InterVLANRouting string `json:"interVlanRouting"`
	FQDN             string `json:"fqdn"`
}

type networkEnvelope struct {
	System struct {
		BasicSettings NetworkSettings `json:"basicSettings"`
	} `json:"system"`
}

func networkPayload(n NetworkSettings) map[string]any {
	return map[string]any{"system": map[string]any{"basicSettings": n}}
}

func (c *Client) GetNetwork() (NetworkSettings, error) {
	var env networkEnvelope
	err := c.Call(networkPayload(NetworkSettings{}), &env)
	return env.System.BasicSettings, err
}

// SetNetwork writes the whole addressing block.
//
// If this changes the address, the AP moves immediately and the connection
// carrying the request dies - that is expected, not a failure. Reconnect on the
// new address to verify.
func (c *Client) SetNetwork(n NetworkSettings) error {
	return c.Call(networkPayload(n), nil)
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
			EthernetMACAddress string `json:"ethernetMacAddress"`
			SysVersion         string `json:"sysVersion"`
			// AltSysVersion is the OTHER firmware slot - the image that is not
			// running. The AP keeps two, and an upgrade overwrites the idle one
			// then boots it, so this is what the current image was upgraded FROM
			// and what a rollback would land on.
			//
			// It is also the one field that might explain the downgrade prompt.
			// Upgrading 10.8.10.10 -> 11.8.0.9 raised the prompt; upgrading
			// 10.8.13.2 -> 11.8.0.9 did not, and between those two attempts this
			// field had moved from V10.1.5.1 to V10.8.10.10. That is consistent
			// with the AP comparing the offered image against the slot it is
			// about to overwrite rather than against the running one - one data
			// point, not a proven rule, so read it before an upgrade and record
			// what happened.
			AltSysVersion        string `json:"altSysVersion"`
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
			"ethernetMacAddress": "", "sysVersion": "", "altSysVersion": "",
			"sysCountryRegion": "",
			"defaultGateway":   "", "defaultGatewayStatus": "", "ipAddress": "",
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
	return c.logoutLocked()
}

// logoutLocked releases the session. Callers hold c.mu.
func (c *Client) logoutLocked() error {
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

// --- admin password ---------------------------------------------------------

// SetAdminPassword changes the AP's admin credential.
//
// The field is newadminPasswd, a sibling of the other basicSettings fields.
// It is NOT the adminPasswd used at login - that one authenticates, this one
// replaces. Sending adminPasswd here does nothing and reports success.
//
// The name was recovered from the AP's own js/vendor.bundle.js, where the
// setup form builds basicSettings.newadminPasswd from the new-password input.
// It does not appear in the api_entries list in scripts/wax630e_api.json;
// changeUserPassword and validateOldPwd do appear there, but those are the
// day-zero paths and are not what the configured AP's settings page uses.
//
// Unlike the router, the AP does NOT ask for the old password - the session
// is the proof of authorisation. Verified against firmware on 2026-09-05:
// reply {"status": 0}, the old credential rejected with err_code 26 on the
// next login, the new one accepted.
//
// A failed login LEAKS A SESSION SLOT on this hardware, and the AP starts
// answering 401 to everyone - the browser included - once the table fills.
// Always Logout after changing the password, then build a fresh Client.
func (c *Client) SetAdminPassword(newPassword string) error {
	if newPassword == "" {
		return fmt.Errorf("new password is required")
	}
	return c.Call(map[string]any{
		"system": map[string]any{
			"basicSettings": map[string]any{"newadminPasswd": newPassword},
		},
	}, nil)
}

// --- firmware ---------------------------------------------------------------
//
// The AP checks NETGEAR for updates on its own and caches the answer under
// system.FwUpdate. That subtree is NOT discoverable by probing: this API is
// query-by-example and an unrecognised key echoes back an empty object rather
// than erroring, so a wrong guess is indistinguishable from "no such setting".
// Every guess at system.maintenance.firmware, firmwareUpgrade and the like
// came back empty. The real path was found by hooking the web UI's own XHR.
//
// THE FIELD THAT MATTERS IS ImageAvailable. system.monitor.newVersion exists
// but reads the literal string "Invalid String" until a check has run, which
// looks like a parse failure and is really just "not checked yet".
type FirmwareStatus struct {
	// ImageAvailable is "1" when a newer release exists.
	ImageAvailable string `json:"ImageAvailable"`
	// ImageVersion is the AVAILABLE version, e.g. "V12.8.0.6" - not the
	// running one, which is system.monitor.sysVersion.
	ImageVersion    string `json:"ImageVersion"`
	LastCheckedDate string `json:"LastcheckedDate"`
	ReleaseNotesURL string `json:"releasenotesurl"`
}

type firmwareEnvelope struct {
	System struct {
		FwUpdate FirmwareStatus `json:"FwUpdate"`
	} `json:"system"`
}

// UpgradeAvailable reports whether the AP believes a newer release exists.
func (f FirmwareStatus) UpgradeAvailable() bool { return f.ImageAvailable == "1" }

// GetFirmwareStatus reads the AP's cached view of available firmware.
//
// USE THIS BEFORE UPLOADING AN IMAGE BY HAND. The AP compares whatever file it
// is given against its running version and warns about a DOWNGRADE - including
// a factory reset and loss of every wireless setting - if it cannot read a
// newer version out of that file. A .zip straight from the download page will
// do exactly that, because the archive wraps the real image; the file to
// upload is the .tar inside it. When ImageAvailable is "1" the AP can fetch
// the correct image itself and no upload is needed at all.
func (c *Client) GetFirmwareStatus() (FirmwareStatus, error) {
	var out firmwareEnvelope
	err := c.Call(map[string]any{
		"system": map[string]any{
			"FwUpdate": map[string]any{
				"ImageAvailable": "", "ImageVersion": "",
				"LastcheckedDate": "", "releasenotesurl": "",
			},
		},
	}, &out)
	return out.System.FwUpdate, err
}

// --- SSIDs ------------------------------------------------------------------
//
// WHY THIS EXISTS: the AP's wireless configuration is the only device state on
// this network with no record anywhere outside the device itself. A factory
// reset - which a mis-handled firmware upload will offer to perform - loses
// every SSID, passphrase, VLAN binding and radio setting, and re-onboarding
// every wireless client is the kind of afternoon worth spending an API call to
// avoid.
//
// The SSIDs live at system.vapSettings.vapSettingTable.wlanN.vapM, three
// radios by eight virtual APs. Enumerating that by hand is 24 lookups; the web
// UI instead asks wlanSettings.wlanSettingTable.ssidGetDetails, which returns
// the populated ones in one call. That key is a REQUEST FLAG, not a stored
// setting - it does not appear in the reply.
type SSIDDetails map[string]any

type ssidEnvelope struct {
	System struct {
		WlanSettings struct {
			WlanSettingTable map[string]any `json:"wlanSettingTable"`
		} `json:"wlanSettings"`
	} `json:"system"`
}

// GetSSIDDetails returns every configured SSID as the device reports it.
//
// Returned as a loose map on purpose. The per-SSID field set is large and
// firmware-dependent - captive portal, scheduling, bandwidth limits, MPSK and
// 802.1x each add their own keys - and modelling it as a struct would silently
// drop whatever this firmware happens to add. For capture-before-reset the
// point is to lose nothing, so nothing is filtered.
//
// CONTAINS SECRETS. Passphrases are in here. Persist the result somewhere that
// deserves them - Vault, not a git repo, and not a terminal scrollback.
func (c *Client) GetSSIDDetails() (SSIDDetails, error) {
	var out ssidEnvelope
	if err := c.Call(map[string]any{
		"system": map[string]any{
			"wlanSettings": map[string]any{
				"wlanSettingTable": map[string]any{"ssidGetDetails": ""},
			},
		},
	}, &out); err != nil {
		return nil, err
	}
	return SSIDDetails(out.System.WlanSettings.WlanSettingTable), nil
}

// --- firmware upgrade -------------------------------------------------------
//
// THE UPGRADE API IS NOT ON /socketCommunication. It posts to /LogFile, which
// is not a name anybody would guess and is the reason this went undiscovered
// until the web UI's own XHR was hooked. It also does not use the
// query-by-example shape the rest of this client speaks; it takes a numeric
// method code.
//
//	{"method":7,"fwUpgrade":0}  start the online upgrade
//	{"method":6,"fwPercent":N}  poll progress
//
// PERCENT IS NOT A PERCENTAGE. 100 means the image finished downloading, and
// 110 is an out-of-range SENTINEL meaning the flash failed - the UI turns it
// into "An error occurred while updating the firmware" with no further detail.
// Anything above 100 is a failure code, not progress.
//
// Observed on V10.8.10.10 offered V12.8.0.6: the download reaches 100 and then
// every subsequent poll returns 110. The image transfers fine; applying it is
// what fails, which points at a version-jump restriction rather than a bad
// file or a network problem. The local-upload path refuses the same image as a
// "downgrade" requiring a factory reset, which is consistent with the AP
// mishandling the major version when comparing 12.8.0.6 against 10.8.10.10.
const (
	fwMethodStart = 7
	fwMethodPoll  = 6

	// FirmwareDownloadComplete is the percent value meaning the transfer
	// finished. Values ABOVE it are failures.
	FirmwareDownloadComplete = 100
	// FirmwareFailed is the sentinel the firmware returns when the flash
	// fails after a successful download.
	FirmwareFailed = 110
)

type fwProgressReply struct {
	Status  int `json:"status"`
	Percent int `json:"percent"`
}

// FirmwareProgress is one poll of an in-flight upgrade.
type FirmwareProgress struct {
	Percent int
}

// Downloading reports whether the image is still transferring.
func (p FirmwareProgress) Downloading() bool { return p.Percent < FirmwareDownloadComplete }

// Failed reports whether the AP has given up. See the sentinel note above:
// any percent beyond 100 is an error code rather than progress.
func (p FirmwareProgress) Failed() bool { return p.Percent > FirmwareDownloadComplete }

func (c *Client) fwPost(payload any, out any) error {
	return c.fwPostTo("/LogFile", payload, out)
}

// fwPostTo posts to one of the AP's non-socketCommunication endpoints.
func (c *Client) fwPostTo(path string, payload any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
		if !c.keepAlive {
			defer c.logoutLocked()
		}
	}
	_, raw, err := c.post(payload, map[string]string{"__path": path, "security": c.token})
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// GetFirmwareProgress polls an in-flight upgrade.
func (c *Client) GetFirmwareProgress() (FirmwareProgress, error) {
	var r fwProgressReply
	if err := c.fwPost(map[string]any{"method": fwMethodPoll, "fwPercent": 1}, &r); err != nil {
		return FirmwareProgress{}, err
	}
	return FirmwareProgress{Percent: r.Percent}, nil
}

// StartFirmwareUpgrade begins the ONLINE upgrade: the AP fetches the image
// NETGEAR advertises and flashes it itself.
//
// DESTRUCTIVE AND SLOW. The AP reboots on success and every wireless client
// drops. Check GetFirmwareStatus().UpgradeAvailable() first, and back up the
// wireless configuration with GetSSIDDetails() before calling this - a failed
// or forced upgrade on this device can end in a factory reset, which loses
// every SSID and passphrase.
//
// Returns immediately; poll GetFirmwareProgress for the outcome.
func (c *Client) StartFirmwareUpgrade() error {
	return c.fwPost(map[string]any{"method": fwMethodStart, "fwUpgrade": 0}, nil)
}

// --- upgrade path -----------------------------------------------------------
//
// THE AP'S VERSION COMPARISON IGNORES THE MAJOR VERSION. It compares from the
// SECOND field onward, so it decides 11.8.0.9 and 12.8.0.6 are both OLDER than
// 10.8.10.10:
//
//	10.8.10.10 vs 11.8.0.9   ->  8.10.10 vs 8.0.9   -> "downgrade"
//	10.8.10.10 vs 12.8.0.6   ->  8.10.10 vs 8.0.6   -> "downgrade"
//	10.8.10.10 vs 10.8.13.2  ->  8.10.10 vs 8.13.2  -> clean upgrade
//
// THAT RULE IS INCOMPLETE, and the correction matters more than the rule.
// From 10.8.10.10 both 11.8.0.9 and 12.8.0.6 did produce the prompt. But once
// the AP was on 10.8.13.2, 11.8.0.9 applied with NO prompt and NO factory
// reset - which the field-comparison model says should have been impossible
// (8.13.2 vs 8.0.9 reads as older). What else changed is that the backup slot
// went from V10.1.5.1 to V10.8.10.10, hinting the AP may compare against the
// slot it is overwriting rather than the running image. That is one data
// point, so it is recorded as an observation and not asserted as the rule.
//
// The practical guidance: step up one release at a time, and TRY it - the
// prompt is a warning with a Cancel button, not a refusal. Back up with
// GetSSIDDetails first anyway, because when the reset does happen it takes
// every SSID and passphrase with it.
//
// AND CHECK THE RELEASE NOTES OF THE INTERMEDIATE, NOT JUST THE TARGET. This
// was learned the expensive way. 10.8.13.2 was picked purely because it dodged
// the downgrade prompt; the release notes for 11.8.0.9 say:
//
//	"Fixes the issue where the STP was enabled on the AP with incorrect
//	 Forward Delay causing intermediate switch to malfunction or crash."
//
// 10.8.13.2 predates that fix. The AP rebooted into it and the MS510TXUP it
// plugs into went down minutes later, taking every PoE-powered cluster node
// with it and requiring a physical power cycle. A version that is "safe" by
// the upgrade-path rule can still be unsafe for the switch it is attached to.
type UpgradeStep struct {
	Version string
	// CleanUpgrade records whether the AP applies this release WITHOUT the
	// downgrade prompt that factory-resets it. See Verified: where that is
	// false, this field is a prediction and predictions here have been wrong.
	CleanUpgrade bool
	// Verified is true only where the hop has actually been performed on this
	// hardware. An unverified CleanUpgrade is a guess, and the guessing record
	// on this device is poor - a model that had 11.8.0.9 costing a factory
	// reset was contradicted by simply doing it.
	Verified bool
	// Warning is a known regression or hazard in this specific release.
	Warning string
}

// KnownUpgradePath is the WAX630E release ladder, newest last, with what each
// step costs. Ordering is NETGEAR's, not semantic-version ordering.
var KnownUpgradePath = []UpgradeStep{
	{Version: "10.8.11.4", CleanUpgrade: true, Verified: false,
		Warning: "predates the 11.8.0.9 AP-STP fix that crashes an attached switch"},
	{Version: "10.8.12.7", CleanUpgrade: true, Verified: false,
		Warning: "predates the 11.8.0.9 AP-STP fix that crashes an attached switch"},
	{Version: "10.8.13.2", CleanUpgrade: true, Verified: true,
		Warning: "VERIFIED clean from 10.8.10.10, config kept. But it STILL predates the " +
			"11.8.0.9 AP-STP fix and was observed taking down the MS510TXUP it plugs into, " +
			"twice, each time needing a physical power cycle. Do not stop here"},
	{Version: "11.8.0.9", CleanUpgrade: true, Verified: true,
		Warning: "VERIFIED clean from 10.8.13.2 - no downgrade prompt, no factory reset, SSIDs kept. " +
			"First release with the AP-STP fix, so this is the one that stops the attached switch " +
			"crashing. An earlier model here predicted a factory reset for this hop and was WRONG"},
	{Version: "12.5.0.14", CleanUpgrade: true, Verified: false, Warning: ""},
	{Version: "12.8.0.6", CleanUpgrade: true, Verified: false,
		Warning: "current latest; adds SNMPv2 and fixes random AP reboots, client disconnects " +
			"and LLDP not being sent"},
}

// NextUpgradeStep returns the next release to install from the running one,
// and whether it applies without the factory-reset prompt.
//
// Returns nil when already at the newest known release.
func NextUpgradeStep(running string) *UpgradeStep {
	running = strings.TrimPrefix(strings.TrimSpace(running), "V")
	idx := -1
	for i, s := range KnownUpgradePath {
		if s.Version == running {
			idx = i
			break
		}
	}
	// Unknown or older than the table: start at the beginning.
	if idx < 0 {
		return &KnownUpgradePath[0]
	}
	if idx+1 >= len(KnownUpgradePath) {
		return nil
	}
	return &KnownUpgradePath[idx+1]
}

// FirmwareURL is where NETGEAR publishes a given release. The download is a
// ZIP wrapping release notes and the real image; upload the .tar inside it,
// never the .zip - the AP cannot read a version out of the archive and treats
// it as a downgrade.
func FirmwareURL(version string) string {
	v := strings.TrimPrefix(strings.TrimSpace(version), "V")
	return "https://www.downloads.netgear.com/files/GDC/WAX630E/WAX630E_firmware_V" + v + ".zip"
}

// UpgradeFromSFTP tells the AP to fetch a firmware image over SFTP and flash
// it. This is the path that actually works on this device.
//
// POST /upgradeSFTP - a THIRD endpoint, distinct from /socketCommunication
// (everything else) and /LogFile (the online upgrade). Its body is flat JSON,
// not the query-by-example shape:
//
//	{"username","password","remoteIP","remoteFile","check":1}  ->  {"status":0}
//
// remoteFile is relative to the SFTP user's home directory.
//
// WHY SFTP RATHER THAN THE OBVIOUS PATHS. The online upgrade (see
// StartFirmwareUpgrade) downloads to 100% and then fails to flash, returning
// the 110 sentinel forever. The browser upload form caps at a size below a
// real image. SFTP is the only route that both transfers and applies, and it
// has the useful property that the AP pulls rather than being pushed to, so a
// slow control channel does not matter.
//
// DESTRUCTIVE. The AP reboots on success and every wireless client drops. Back
// up with GetSSIDDetails first: depending on the version being applied, the AP
// may decide the image is a downgrade and factory-reset itself, losing every
// SSID and passphrase. Returns as soon as the AP accepts the job - the flash
// and reboot happen afterwards.
func (c *Client) UpgradeFromSFTP(server, username, password, remoteFile string) error {
	var out struct {
		Status int `json:"status"`
	}
	if err := c.fwPostTo("/upgradeSFTP", map[string]any{
		"username":   username,
		"password":   password,
		"remoteIP":   server,
		"remoteFile": remoteFile,
		// The UI always sends 1. Its meaning is not documented anywhere the
		// device exposes; it is reproduced rather than reasoned about.
		"check": 1,
	}, &out); err != nil {
		return err
	}
	if out.Status != 0 {
		return fmt.Errorf("the access point rejected the SFTP upgrade (status %d)", out.Status)
	}
	return nil
}
