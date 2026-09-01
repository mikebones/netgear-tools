package provider

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

// client speaks the NETGEAR PR60X's local management protocol: JSON-RPC 2.0
// over a single POST endpoint at /socketCommunication.
//
// The auth sequence is not obvious and all three steps are load-bearing
// (verified against firmware 2.7.0.111 on 2026-08-31):
//
//  1. GET / to obtain the lhttpdsid session cookie. Skipping this makes the
//     login call below fail with -32602 "invalid params" - which looks like a
//     bad password but is actually a missing session.
//  2. POST login {username, password} -> result.token, WITH that cookie.
//  3. Every subsequent call needs BOTH the cookie and a "Security: <token>"
//     header. The token alone returns 401; this was confirmed by replaying a
//     call with the cookie jar detached.
//
// See README.md and scripts/schema.json for the full protocol notes.
type client struct {
	endpoint string
	username string
	password string

	httpClient *http.Client

	// mu serializes every RPC. This is deliberate and not just for memory
	// safety: the device's backend config daemon degrades under concurrent
	// or rapid-fire load. Hitting it with ~49 back-to-back reads wedged it
	// into returning HTTP 500 "Failed to call process_configd_request.
	// ret = -1" for every subsequent call until it recovered. Terraform
	// walks independent resources in parallel by default, so without this
	// lock an apply of a dozen rules would reproduce exactly that failure.
	mu       sync.Mutex
	token    string
	lastCall time.Time
}

// minInterval is the floor between two RPCs, for the configd reason above.
const minInterval = 250 * time.Millisecond

func newClient(endpoint, username, password string, insecure bool) (*client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	transport := &http.Transport{}
	if insecure {
		// The PR60X ships a self-signed certificate for its LAN address and
		// there is no practical way to pin a real one on a private IP.
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &client{
		endpoint: endpoint,
		username: username,
		password: password,
		httpClient: &http.Client{
			Jar:       jar,
			Transport: transport,
			Timeout:   60 * time.Second,
		},
	}, nil
}

// rpcError is a JSON-RPC 2.0 error object as the device returns it.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("rpc error %d", e.Code)
	}
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

// prime performs the GET / that establishes the lhttpdsid cookie.
func (c *client) prime() error {
	req, err := http.NewRequest(http.MethodGet, c.endpoint+"/", nil)
	if err != nil {
		return fmt.Errorf("build prime request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("prime session: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("prime session returned %d", resp.StatusCode)
	}
	return nil
}

// post sends one JSON-RPC envelope. Caller must hold c.mu.
func (c *client) post(method string, params any, out any) error {
	if since := time.Since(c.lastCall); since < minInterval {
		time.Sleep(minInterval - since)
	}

	if params == nil {
		params = map[string]any{}
	}
	body, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0", ID: 1, Method: method, Params: params,
	})
	if err != nil {
		return fmt.Errorf("marshal %s params: %w", method, err)
	}

	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/socketCommunication", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build %s request: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		req.Header.Set("Security", c.token)
	}

	resp, err := c.httpClient.Do(req)
	c.lastCall = time.Now()
	if err != nil {
		return fmt.Errorf("call %s: %w", method, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read %s response: %w", method, err)
	}

	var parsed rpcResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("decode %s response (HTTP %d): %w", method, resp.StatusCode, err)
	}
	if parsed.Error != nil && parsed.Error.Code != 0 {
		return parsed.Error
	}
	if out != nil && len(parsed.Result) > 0 {
		if err := json.Unmarshal(parsed.Result, out); err != nil {
			return fmt.Errorf("decode %s result: %w", method, err)
		}
	}
	return nil
}

// login primes the session and exchanges credentials for a token.
// Caller must hold c.mu.
func (c *client) login() error {
	c.token = ""
	if err := c.prime(); err != nil {
		return err
	}
	var res struct {
		Token string `json:"token"`
	}
	params := map[string]string{"username": c.username, "password": c.password}
	if err := c.post("login", params, &res); err != nil {
		return fmt.Errorf("login as %q: %w", c.username, err)
	}
	if res.Token == "" {
		return fmt.Errorf("login as %q returned no token", c.username)
	}
	c.token = res.Token
	return nil
}

// isSessionError reports whether an error means "log in again" rather than
// "this request was wrong". 401 is the device's unauthenticated code; -32602
// on login specifically means the session cookie was missing.
func isSessionError(err error) bool {
	var re *rpcError
	if !asRPCError(err, &re) {
		return false
	}
	return re.Code == 401
}

func asRPCError(err error, target **rpcError) bool {
	re, ok := err.(*rpcError)
	if ok {
		*target = re
	}
	return ok
}

// call runs one RPC, logging in first if needed and retrying once if the
// session has expired underneath us.
func (c *client) call(method string, params any, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
	}

	err := c.post(method, params, out)
	if err != nil && isSessionError(err) {
		// Session expired (the device has a GUI idle timeout that applies to
		// API sessions too). Re-authenticate once and replay.
		if lerr := c.login(); lerr != nil {
			return lerr
		}
		err = c.post(method, params, out)
	}
	return err
}

// doubleWrapped lists the methods whose JSON-RPC "result" is itself an object
// with a single "result" key wrapping the real payload, e.g.
//
//	{"jsonrpc":"2.0","id":1,"result":{"result":[ ...vlans... ]}}
//
// The rest return their payload directly under "result". There is no pattern
// to which do which - it is per-method inconsistency in the firmware - so the
// set is enumerated from a full sweep of every get* method rather than
// guessed. Determined 2026-08-31 against firmware 2.7.0.111; re-check with
// scripts/discover.py after a firmware upgrade.
var doubleWrapped = map[string]bool{
	"getMacAclTable":      true,
	"getPasswordRecovery": true,
	"getPortSettings":     true,
	"getVlanPorts":        true,
	"getVlanProfiles":     true,
	"getWanProfiles":      true,
}

// callResult is call() with the double-wrap quirk handled. Read helpers
// should use this rather than call() directly.
func (c *client) callResult(method string, params any, out any) error {
	if !doubleWrapped[method] {
		return c.call(method, params, out)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := c.call(method, params, &envelope); err != nil {
		return err
	}
	if len(envelope.Result) == 0 || out == nil {
		return nil
	}
	if err := json.Unmarshal(envelope.Result, out); err != nil {
		return fmt.Errorf("decode %s inner result: %w", method, err)
	}
	return nil
}

// logout releases the session. Best effort - an appliance this size has a
// finite session table, so it is worth not leaking them.
func (c *client) logout() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		return
	}
	_ = c.post("logout", nil, nil)
	c.token = ""
}

// --- Device info -----------------------------------------------------------

type deviceInfo struct {
	ProductID                string `json:"productId"`
	SerialNumber             string `json:"serialNumber"`
	FirmwareVersion          string `json:"firmwareVersion"`
	BootloaderVersion        string `json:"bootloaderVersion"`
	EthernetMAC              string `json:"ethernetMAC"`
	Region                   string `json:"region"`
	ReleaseType              string `json:"releaseType"`
	InsightMode              string `json:"insightMode"`
	InsightStatus            string `json:"insightStatus"`
	Uptime                   string `json:"uptime"`
	FanSpeedRPM              int64  `json:"fanSpeedRPM"`
	SystemTemperatureCelsius int64  `json:"systemTemperatureCelsius"`
}

func (c *client) getDeviceInfo() (*deviceInfo, error) {
	var out deviceInfo
	if err := c.callResult("getDeviceInfo", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type managementMode struct {
	Mode string `json:"mode"`
}

func (c *client) getManagementMode() (*managementMode, error) {
	var out managementMode
	if err := c.callResult("getManagementMode", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Service profiles ------------------------------------------------------

// serviceProfile is a named protocol/port definition. Port-forwarding rules
// reference these BY NAME, not by id, so the name is the real identity.
//
// Shape confirmed from live getServiceProfiles output:
//
//	{"id":13,"name":"PLEX","proto":"tcp","startPort":32400,"endPort":32400}
//	{"id":6,"name":"ICMP Destination Unreachable","proto":"icmp","icmpType":3}
//	{"id":0,"name":"All Traffic","proto":"all"}
//
// startPort/endPort are absent for proto "all" and "icmp"; icmpType is
// absent for everything else. Hence the omitempty pointers.
type serviceProfile struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Proto     string `json:"proto"`
	StartPort *int64 `json:"startPort,omitempty"`
	EndPort   *int64 `json:"endPort,omitempty"`
	ICMPType  *int64 `json:"icmpType,omitempty"`

	// Action is a write-only discriminator the device requires on mutating
	// calls ("add" or "edit"). It is never present in read responses, hence
	// omitempty.
	Action string `json:"action,omitempty"`
}

func (c *client) listServiceProfiles() ([]serviceProfile, error) {
	var out []serviceProfile
	if err := c.callResult("getServiceProfiles", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *client) getServiceProfileByName(name string) (*serviceProfile, error) {
	all, err := c.listServiceProfiles()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, nil
}

// WRITE SHAPES
//
// Confirmed by round trip against firmware 2.7.0.111 on 2026-08-31
// (scripts/roundtrip.py, scripts/roundtrip2.py). The device is picky in two
// non-obvious ways, and getting either wrong yields HTTP 500
// "Failed to call process_configd_request" rather than a useful error:
//
//   add:    [ {...fields, "id": <next free id>, "action": "add"} ]
//   edit:   [ {...fields, "id": <existing id>,  "action": "edit"} ]
//   delete: [ <id>, ... ]
//
//  1. The payload is always an ARRAY of rows, even for a single object. A
//     bare object is rejected.
//  2. The CALLER allocates the id on create. The device does not assign one;
//     it stores whatever id is sent. Hence nextServiceProfileID below.
//
// This mirrors the web UI, which posts its whole edited grid back as rows
// carrying per-row action discriminators.

// nextServiceProfileID returns one past the highest existing id. Callers must
// hold no lock; this performs its own read.
func (c *client) nextServiceProfileID() (int64, error) {
	all, err := c.listServiceProfiles()
	if err != nil {
		return 0, err
	}
	var max int64 = -1
	for _, p := range all {
		if p.ID > max {
			max = p.ID
		}
	}
	return max + 1, nil
}

// addServiceProfile allocates an id, creates the profile, and returns the id
// it used.
func (c *client) addServiceProfile(p serviceProfile) (int64, error) {
	id, err := c.nextServiceProfileID()
	if err != nil {
		return 0, err
	}
	p.ID = id
	p.Action = "add"
	if err := c.call("addServiceProfiles", []serviceProfile{p}, nil); err != nil {
		return 0, err
	}
	return id, nil
}

func (c *client) editServiceProfile(p serviceProfile) error {
	p.Action = "edit"
	return c.call("editServiceProfiles", []serviceProfile{p}, nil)
}

func (c *client) deleteServiceProfile(id int64) error {
	return c.call("deleteServiceProfiles", []int64{id}, nil)
}

// --- Port forwarding -------------------------------------------------------

// portForwardingRule maps a WAN-facing service to an internal address.
//
// Shape confirmed from live getPortForwardingRules output:
//
//	{"id":1,"enabled":1,"externalService":"WG","internalService":"WG",
//	 "destIpAddress":"192.168.1.70","srcIpAddress":"Any",
//	 "wanInputInterface":"wan","wanIpAddress":""}
//
// externalService/internalService are service-profile NAMES. They can differ,
// and that is how this device expresses external-to-internal port translation:
// an "SSH-ALT" profile on the WAN side pointing at a plain "SSH" profile on the
// LAN side. There is no separate "external port" field.
type portForwardingRule struct {
	ID                int64  `json:"id"`
	Enabled           int64  `json:"enabled"`
	ExternalService   string `json:"externalService"`
	InternalService   string `json:"internalService"`
	DestIPAddress     string `json:"destIpAddress"`
	SrcIPAddress      string `json:"srcIpAddress"`
	WANInputInterface string `json:"wanInputInterface"`
	WANIPAddress      string `json:"wanIpAddress"`

	// Action is the write-only discriminator - see "WRITE SHAPES" above.
	Action string `json:"action,omitempty"`
}

func (c *client) listPortForwardingRules() ([]portForwardingRule, error) {
	var out []portForwardingRule
	if err := c.callResult("getPortForwardingRules", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// getPortForwardingRuleByID looks a rule up by its device-assigned id.
// Returns (nil, nil) when the rule is gone, so callers can drop it from
// state rather than erroring.
func (c *client) getPortForwardingRuleByID(id int64) (*portForwardingRule, error) {
	all, err := c.listPortForwardingRules()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, nil
}

// Same array-plus-action contract as service profiles - see "WRITE SHAPES".

func (c *client) nextPortForwardingRuleID() (int64, error) {
	all, err := c.listPortForwardingRules()
	if err != nil {
		return 0, err
	}
	var max int64 = -1
	for _, r := range all {
		if r.ID > max {
			max = r.ID
		}
	}
	return max + 1, nil
}

// addPortForwardingRule allocates an id, creates the rule, and returns the id
// it used.
func (c *client) addPortForwardingRule(r portForwardingRule) (int64, error) {
	id, err := c.nextPortForwardingRuleID()
	if err != nil {
		return 0, err
	}
	r.ID = id
	r.Action = "add"
	if err := c.call("addPortForwardingRules", []portForwardingRule{r}, nil); err != nil {
		return 0, err
	}
	return id, nil
}

func (c *client) editPortForwardingRule(r portForwardingRule) error {
	r.Action = "edit"
	return c.call("editPortForwardingRules", []portForwardingRule{r}, nil)
}

func (c *client) deletePortForwardingRule(id int64) error {
	return c.call("deletePortForwardingRules", []int64{id}, nil)
}

// --- Static routes ---------------------------------------------------------

type staticRoute struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Destination string `json:"destination"`
	Netmask     string `json:"netmask"`
	Gateway     string `json:"gateway"`
	Metric      int64  `json:"metric"`
	Interface   string `json:"interface"`
	Enabled     int64  `json:"enabled"`

	Action string `json:"action,omitempty"`
}

func (c *client) listStaticRoutes() ([]staticRoute, error) {
	var out []staticRoute
	if err := c.callResult("getStaticRoutes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *client) getStaticRouteByID(id int64) (*staticRoute, error) {
	all, err := c.listStaticRoutes()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, nil
}

// NOTE: the live device has zero static routes, so the field names above are
// taken from the web UI's form rather than from an observed response, and the
// add/edit/delete calls follow the confirmed array-plus-action contract but
// have not themselves been exercised. Verify with a throwaway route before
// relying on this resource.
func (c *client) addStaticRoute(r staticRoute) (int64, error) {
	all, err := c.listStaticRoutes()
	if err != nil {
		return 0, err
	}
	var max int64 = -1
	for _, x := range all {
		if x.ID > max {
			max = x.ID
		}
	}
	r.ID = max + 1
	r.Action = "add"
	if err := c.call("addStaticRoutes", []staticRoute{r}, nil); err != nil {
		return 0, err
	}
	return r.ID, nil
}

func (c *client) editStaticRoute(r staticRoute) error {
	r.Action = "edit"
	return c.call("editStaticRoutes", []staticRoute{r}, nil)
}

func (c *client) deleteStaticRoute(id int64) error {
	return c.call("deleteStaticRoutes", []int64{id}, nil)
}

// --- VLAN profiles (read-only) ---------------------------------------------

type vlanIPv4Settings struct {
	IPAddress            string   `json:"ipAddress"`
	Netmask              string   `json:"netmask"`
	DHCPServerEnabled    int64    `json:"dhcpServerEnabled"`
	DHCPStartIPv4Address string   `json:"dhcpStartIpv4Address"`
	DHCPEndIPv4Address   string   `json:"dhcpEndIpv4Address"`
	DHCPLeaseTime        int64    `json:"dhcpLeaseTime"`
	DHCPDNSType          string   `json:"dhcpDnsType"`
	DHCPDNSAddr          []string `json:"dhcpDnsAddr"`
	DHCPDomainName       string   `json:"dhcpDomainName"`
}

type vlanProfile struct {
	VLANID           int64            `json:"vlanId"`
	Name             string           `json:"name"`
	Enabled          int64            `json:"enabled"`
	MACAddress       string           `json:"macAddress"`
	InterVLANRouting int64            `json:"interVlanRouting"`
	DeviceManagement int64            `json:"deviceManagement"`
	IPv4Settings     vlanIPv4Settings `json:"ipv4Settings"`
}

func (c *client) listVLANProfiles() ([]vlanProfile, error) {
	var out []vlanProfile
	if err := c.callResult("getVlanProfiles", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- DHCP leases (read-only) -----------------------------------------------

type dhcpLease struct {
	HostName        string `json:"hostName"`
	IPAddr          string `json:"ipAddr"`
	MACAddr         string `json:"macAddr"`
	LeaseExpireTime int64  `json:"leaseExpireTime"`
	Type            string `json:"type"`
}

// listDHCPLeases returns leases keyed by VLAN name, e.g. "VLAN1".
func (c *client) listDHCPLeases() (map[string][]dhcpLease, error) {
	out := map[string][]dhcpLease{}
	if err := c.callResult("getDhcpLeases", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- WAN status (read-only) ------------------------------------------------

type wanStatus struct {
	Status     string
	WANType    string
	PublicIPs  []string
	Interfaces int
}

func (c *client) getWANStatus() (*wanStatus, error) {
	var st struct {
		Status string `json:"status"`
	}
	if err := c.callResult("getInternetStatus", nil, &st); err != nil {
		return nil, err
	}
	var wt struct {
		WANType string `json:"wanType"`
	}
	if err := c.callResult("getWanType", nil, &wt); err != nil {
		return nil, err
	}
	var ips []string
	if err := c.callResult("getExternalPublicIpAddress", nil, &ips); err != nil {
		return nil, err
	}
	return &wanStatus{Status: st.Status, WANType: wt.WANType, PublicIPs: ips}, nil
}
