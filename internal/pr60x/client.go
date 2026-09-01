// Package pr60x speaks the NETGEAR PR60X's local management protocol.
// Shared by the Terraform provider and the Prometheus exporter in this
// repo so the auth sequence, configd pacing and response quirks live in
// exactly one place.
package pr60x

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client speaks the NETGEAR PR60X's local management protocol: JSON-RPC 2.0
// over a single POST endpoint at /socketCommunication.
//
// The auth sequence is not obvious and all three steps are load-bearing
// (verified against firmware 2.7.0.111 on 2026-08-31):
//
//  1. GET / to obtain the lhttpdsid session cookie. Skipping this makes the
//     login Call below fail with -32602 "invalid params" - which looks like a
//     bad password but is actually a missing session.
//  2. POST login {username, password} -> result.token, WITH that cookie.
//  3. Every subsequent Call needs BOTH the cookie and a "Security: <token>"
//     header. The token alone returns 401; this was confirmed by replaying a
//     Call with the cookie jar detached.
//
// See README.md and scripts/schema.json for the full protocol notes.
type Client struct {
	endpoint string
	username string
	password string

	httpClient *http.Client

	// mu serializes every RPC. This is deliberate and not just for memory
	// safety: the device's backend config daemon degrades under concurrent
	// or rapid-fire load. Hitting it with ~49 back-to-back reads wedged it
	// into returning HTTP 500 "Failed to Call process_configd_request.
	// ret = -1" for every subsequent Call until it recovered. Terraform
	// walks independent resources in parallel by default, so without this
	// lock an apply of a dozen rules would reproduce exactly that failure.
	mu       sync.Mutex
	token    string
	lastCall time.Time
}

// minInterval is the floor between two RPCs, for the configd reason above.
const minInterval = 250 * time.Millisecond

func NewClient(endpoint, username, password string, insecure bool) (*Client, error) {
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

	return &Client{
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

// RPCError is a JSON-RPC 2.0 error object as the device returns it.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
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
	Error   *RPCError       `json:"error"`
}

// prime performs the GET / that establishes the lhttpdsid cookie.
func (c *Client) prime() error {
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
func (c *Client) post(method string, params any, out any) error {
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
		return fmt.Errorf("Call %s: %w", method, err)
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
func (c *Client) login() error {
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
	var re *RPCError
	if !asRPCError(err, &re) {
		return false
	}
	return re.Code == 401
}

func asRPCError(err error, target **RPCError) bool {
	re, ok := err.(*RPCError)
	if ok {
		*target = re
	}
	return ok
}

// Call runs one RPC, logging in first if needed and retrying once if the
// session has expired underneath us.
func (c *Client) Call(method string, params any, out any) error {
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

// CallResult is Call() with the double-wrap quirk handled. Read helpers
// should use this rather than Call() directly.
func (c *Client) CallResult(method string, params any, out any) error {
	if !doubleWrapped[method] {
		return c.Call(method, params, out)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := c.Call(method, params, &envelope); err != nil {
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

// Logout releases the session. Best effort - an appliance this size has a
// finite session table, so it is worth not leaking them.
func (c *Client) Logout() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		return
	}
	_ = c.post("logout", nil, nil)
	c.token = ""
}

// --- Device info -----------------------------------------------------------

type DeviceInfo struct {
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

func (c *Client) GetDeviceInfo() (*DeviceInfo, error) {
	var out DeviceInfo
	if err := c.CallResult("getDeviceInfo", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type ManagementMode struct {
	Mode string `json:"mode"`
}

func (c *Client) GetManagementMode() (*ManagementMode, error) {
	var out ManagementMode
	if err := c.CallResult("getManagementMode", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// --- Service profiles ------------------------------------------------------

// ServiceProfile is a named protocol/port definition. Port-forwarding rules
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
type ServiceProfile struct {
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

func (c *Client) ListServiceProfiles() ([]ServiceProfile, error) {
	var out []ServiceProfile
	if err := c.CallResult("getServiceProfiles", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetServiceProfileByName(name string) (*ServiceProfile, error) {
	all, err := c.ListServiceProfiles()
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
// "Failed to Call process_configd_request" rather than a useful error:
//
//   add:    [ {...fields, "id": <next free id>, "action": "add"} ]
//   edit:   [ {...fields, "id": <existing id>,  "action": "edit"} ]
//   delete: [ <id>, ... ]
//
//  1. The payload is always an ARRAY of rows, even for a single object. A
//     bare object is rejected.
//  2. The CALLER allocates the id on create. The device does not assign one;
//     it stores whatever id is sent. Hence NextServiceProfileID below.
//
// This mirrors the web UI, which posts its whole edited grid back as rows
// carrying per-row action discriminators.

// NextServiceProfileID returns one past the highest existing id. Callers must
// hold no lock; this performs its own read.
func (c *Client) NextServiceProfileID() (int64, error) {
	all, err := c.ListServiceProfiles()
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

// AddServiceProfile allocates an id, creates the profile, and returns the id
// it used.
func (c *Client) AddServiceProfile(p ServiceProfile) (int64, error) {
	id, err := c.NextServiceProfileID()
	if err != nil {
		return 0, err
	}
	p.ID = id
	p.Action = "add"
	if err := c.Call("addServiceProfiles", []ServiceProfile{p}, nil); err != nil {
		return 0, err
	}
	return id, nil
}

func (c *Client) EditServiceProfile(p ServiceProfile) error {
	p.Action = "edit"
	return c.Call("editServiceProfiles", []ServiceProfile{p}, nil)
}

func (c *Client) DeleteServiceProfile(id int64) error {
	return c.Call("deleteServiceProfiles", []int64{id}, nil)
}

// --- Port forwarding -------------------------------------------------------

// PortForwardingRule maps a WAN-facing service to an internal address.
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
type PortForwardingRule struct {
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

func (c *Client) ListPortForwardingRules() ([]PortForwardingRule, error) {
	var out []PortForwardingRule
	if err := c.CallResult("getPortForwardingRules", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetPortForwardingRuleByID looks a rule up by its device-assigned id.
// Returns (nil, nil) when the rule is gone, so callers can drop it from
// state rather than erroring.
func (c *Client) GetPortForwardingRuleByID(id int64) (*PortForwardingRule, error) {
	all, err := c.ListPortForwardingRules()
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

func (c *Client) NextPortForwardingRuleID() (int64, error) {
	all, err := c.ListPortForwardingRules()
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

// AddPortForwardingRule allocates an id, creates the rule, and returns the id
// it used.
func (c *Client) AddPortForwardingRule(r PortForwardingRule) (int64, error) {
	id, err := c.NextPortForwardingRuleID()
	if err != nil {
		return 0, err
	}
	r.ID = id
	r.Action = "add"
	if err := c.Call("addPortForwardingRules", []PortForwardingRule{r}, nil); err != nil {
		return 0, err
	}
	return id, nil
}

func (c *Client) EditPortForwardingRule(r PortForwardingRule) error {
	r.Action = "edit"
	return c.Call("editPortForwardingRules", []PortForwardingRule{r}, nil)
}

func (c *Client) DeletePortForwardingRule(id int64) error {
	return c.Call("deletePortForwardingRules", []int64{id}, nil)
}

// --- Static routes ---------------------------------------------------------

type StaticRoute struct {
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

func (c *Client) ListStaticRoutes() ([]StaticRoute, error) {
	var out []StaticRoute
	if err := c.CallResult("getStaticRoutes", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetStaticRouteByID(id int64) (*StaticRoute, error) {
	all, err := c.ListStaticRoutes()
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
func (c *Client) AddStaticRoute(r StaticRoute) (int64, error) {
	all, err := c.ListStaticRoutes()
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
	if err := c.Call("addStaticRoutes", []StaticRoute{r}, nil); err != nil {
		return 0, err
	}
	return r.ID, nil
}

func (c *Client) EditStaticRoute(r StaticRoute) error {
	r.Action = "edit"
	return c.Call("editStaticRoutes", []StaticRoute{r}, nil)
}

func (c *Client) DeleteStaticRoute(id int64) error {
	return c.Call("deleteStaticRoutes", []int64{id}, nil)
}

// --- VLAN profiles (read-only) ---------------------------------------------

type VLANIPv4Settings struct {
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

type VLANProfile struct {
	VLANID           int64            `json:"vlanId"`
	Name             string           `json:"name"`
	Enabled          int64            `json:"enabled"`
	MACAddress       string           `json:"macAddress"`
	InterVLANRouting int64            `json:"interVlanRouting"`
	DeviceManagement int64            `json:"deviceManagement"`
	IPv4Settings     VLANIPv4Settings `json:"ipv4Settings"`
}

func (c *Client) ListVLANProfiles() ([]VLANProfile, error) {
	var out []VLANProfile
	if err := c.CallResult("getVlanProfiles", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- VLAN DHCP settings (read-modify-write) --------------------------------
//
// editVlanProfiles REPLACES the whole profile, and a profile carries fields
// this provider does not model - rip, vlanPorts, macAddress, sequentialIp,
// dhcpNtpServerAddr and so on. Rebuilding it from a typed struct would
// silently drop them, so edits go through untyped maps and send every field
// back exactly as read, with only the intended key changed.

func (c *Client) GetVLANProfilesRaw() ([]map[string]any, error) {
	var out []map[string]any
	if err := c.CallResult("getVlanProfiles", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) GetVLANProfileRaw(vlanID int64) (map[string]any, error) {
	all, err := c.GetVLANProfilesRaw()
	if err != nil {
		return nil, err
	}
	for _, p := range all {
		if v, ok := p["vlanId"].(float64); ok && int64(v) == vlanID {
			return p, nil
		}
	}
	return nil, nil
}

// VLANDHCPDNS reads the DHCP option 6 list for one VLAN.
func (c *Client) VLANDHCPDNS(vlanID int64) ([]string, error) {
	p, err := c.GetVLANProfileRaw(vlanID)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, fmt.Errorf("no VLAN with id %d", vlanID)
	}
	ipv4, _ := p["ipv4Settings"].(map[string]any)
	raw, _ := ipv4["dhcpDnsAddr"].([]any)
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// SetVLANDHCPDNS rewrites DHCP option 6 for one VLAN, leaving every other
// field of the profile untouched. Changing option 6 cannot partition the
// network: it only affects what future leases advertise, and existing clients
// keep their current resolvers until they renew.
func (c *Client) SetVLANDHCPDNS(vlanID int64, servers []string) error {
	p, err := c.GetVLANProfileRaw(vlanID)
	if err != nil {
		return err
	}
	if p == nil {
		return fmt.Errorf("no VLAN with id %d", vlanID)
	}
	ipv4, ok := p["ipv4Settings"].(map[string]any)
	if !ok {
		return fmt.Errorf("VLAN %d has no ipv4Settings object", vlanID)
	}

	list := make([]any, 0, len(servers))
	for _, s := range servers {
		list = append(list, s)
	}
	ipv4["dhcpDnsAddr"] = list
	if len(servers) > 0 {
		// The device distinguishes an explicit list from "inherit from WAN".
		ipv4["dhcpDnsType"] = "custom"
	}
	p["action"] = "edit"

	return c.Call("editVlanProfiles", []map[string]any{p}, nil)
}

// --- DHCP leases (read-only) -----------------------------------------------

type DHCPLease struct {
	HostName        string `json:"hostName"`
	IPAddr          string `json:"ipAddr"`
	MACAddr         string `json:"macAddr"`
	LeaseExpireTime int64  `json:"leaseExpireTime"`
	Type            string `json:"type"`
}

// ListDHCPLeases returns leases keyed by VLAN name, e.g. "VLAN1".
func (c *Client) ListDHCPLeases() (map[string][]DHCPLease, error) {
	out := map[string][]DHCPLease{}
	if err := c.CallResult("getDhcpLeases", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// --- Remote syslog ---------------------------------------------------------

// RemoteSyslog is a settings singleton, not a collection, so unlike
// ServiceProfile/PortForwardingRule it is sent as a bare object with no id or
// action discriminator. Settings setters and collection setters do not share
// a calling convention on this device.
type RemoteSyslog struct {
	Enabled         int64  `json:"enabled"`
	ServerIPAddress string `json:"serverIpAddress"`
	ServerPort      int64  `json:"serverPort"`
}

func (c *Client) GetRemoteSyslog() (*RemoteSyslog, error) {
	var out RemoteSyslog
	if err := c.CallResult("getRemoteSyslog", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) SetRemoteSyslog(s RemoteSyslog) error {
	return c.Call("setRemoteSyslog", s, nil)
}

// --- WAN status (read-only) ------------------------------------------------

type WANStatus struct {
	Status     string
	WANType    string
	PublicIPs  []string
	Interfaces int
}

func (c *Client) GetWANStatus() (*WANStatus, error) {
	var st struct {
		Status string `json:"status"`
	}
	if err := c.CallResult("getInternetStatus", nil, &st); err != nil {
		return nil, err
	}
	var wt struct {
		WANType string `json:"wanType"`
	}
	if err := c.CallResult("getWanType", nil, &wt); err != nil {
		return nil, err
	}
	var ips []string
	if err := c.CallResult("getExternalPublicIpAddress", nil, &ips); err != nil {
		return nil, err
	}
	return &WANStatus{Status: st.Status, WANType: wt.WANType, PublicIPs: ips}, nil
}

// --- Telemetry (read-only) -------------------------------------------------

// TrafficStatistics numbers arrive as STRINGS, not JSON numbers, and the whole
// payload is wrapped in a single-element array. Both are firmware quirks, not
// choices - hence the string fields and the ParseCounter helper.
type PortStats struct {
	Port        string `json:"Port"`
	TxPackets   string `json:"Txpackets"`
	RxPackets   string `json:"Rxpackets"`
	TxCollision string `json:"TxCollision"`
	TxError     string `json:"TxError"`
	RxError     string `json:"RxError"`
	TxDrop      string `json:"TxDrop"`
	RxDrop      string `json:"RxDrop"`
	TxBytes     string `json:"TxBytes"`
	RxBytes     string `json:"RxBytes"`
	Status      string `json:"Status"`
}

// ParseCounter turns one of the string counters above into a float, returning
// 0 for anything unparseable rather than failing a whole scrape.
func ParseCounter(s string) float64 {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0
	}
	return v
}

func (c *Client) GetTrafficStatistics() ([]PortStats, error) {
	var out []struct {
		TrafficStats struct {
			WiredPortStats []PortStats `json:"wiredPortStats"`
		} `json:"trafficStats"`
	}
	if err := c.CallResult("getTrafficStatistics", nil, &out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out[0].TrafficStats.WiredPortStats, nil
}

type PortLink struct {
	Name       string `json:"name"`
	LinkStatus int64  `json:"linkStatus"`
	LinkSpeed  int64  `json:"linkSpeed"`
}

func (c *Client) GetWiredPortLinkDetails() ([]PortLink, error) {
	var out []PortLink
	if err := c.CallResult("getWiredPortLinkDetails", nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

type Alarm struct {
	Seq            int64  `json:"alarmseq"`
	SysAlarmID     int64  `json:"sysalarmId"`
	AlarmTimestamp int64  `json:"alarmTimestamp"`
	AlarmLevel     int64  `json:"alarmLevel"`
	InfoString     string `json:"infoString"`
	AlarmTime      string `json:"alarmTime"`
}

func (c *Client) GetAlarms() ([]Alarm, error) {
	var out struct {
		AlmList []Alarm `json:"almList"`
	}
	if err := c.CallResult("getAlarms", nil, &out); err != nil {
		return nil, err
	}
	return out.AlmList, nil
}

func (c *Client) GetPendingAlarmCount() (int64, error) {
	var out struct {
		PendingAlarm int64 `json:"pendingAlarm"`
	}
	if err := c.CallResult("getPendingAlarmCount", nil, &out); err != nil {
		return 0, err
	}
	return out.PendingAlarm, nil
}

type WANInterfaceStatus struct {
	Interface string `json:"interface"`
	Status    string `json:"status"`
	UptimeSec int64  `json:"uptimeSec"`
}

func (c *Client) GetDualWANStatus() ([]WANInterfaceStatus, error) {
	var out struct {
		ActiveInterface string               `json:"activeInterface"`
		InterfaceStatus []WANInterfaceStatus `json:"interfaceStatus"`
	}
	if err := c.CallResult("getDualWanStatus", nil, &out); err != nil {
		return nil, err
	}
	return out.InterfaceStatus, nil
}
