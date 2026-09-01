// Package ms510txup speaks the local CGI API of NETGEAR's MS510TXUP smart
// managed switch.
//
// It is the most defended of the four devices in this repo and the only one
// with four independent mechanisms layered on top of each other. All four are
// required; each one alone fails in a way that looks like a different problem.
//
//  1. URL SIGNING. Every URL carries &bj4=md5(<everything after the ?>),
//     computed after the cache-busting &dummy=<ms> is appended. An unsigned
//     request is rejected with HTTP 400 - note 400, so it reads like a
//     malformed URL rather than a missing signature.
//
//  2. PASSWORD OBFUSCATION. The password is never sent in clear. It is hidden
//     inside a 320-len(pw) character string of random alphanumerics; see
//     obfuscatePassword.
//
//  3. THE LOGIN HANDSHAKE. home_loginAuth returns an authId, which is not a
//     session. home_loginStatus is then polled with that authId until it
//     answers {"data":{"status":"ok","sess":...}}. It genuinely returns a
//     non-ok status on the first poll, so the loop is real.
//
//  4. THE RSA CSRF HEADER. `sess` is not a session token either. It base64
//     decodes into three concatenated fields:
//
//     tabid   = sess[0:32]     32-char session id
//     expo    = sess[32:37]    RSA public exponent, always "10001"
//     modulus = sess[37:]      1024-bit RSA modulus, hex
//
//     Every subsequent request must carry
//
//     X-CSRF-XSID: base64(RSA_PKCS1v15(tabid, pubkey))
//
//     The padding is randomised, so the header differs on every request by
//     design. WITHOUT IT THE SWITCH ANSWERS 404 - not 401, not 403 - which is
//     indistinguishable from a wrong URL and is the single most misleading
//     thing about this API.
//
// Writes need a fifth: an xsrf token from home_home, wrapped into the body as
// _ds=1&<fields>&xsrf=<token>&_de=1. Any reply may rotate it.
//
// A caution learned the hard way: THE SWITCH REPORTS save_success FOR WRITES
// IT SILENTLY IGNORED. Unknown or partial field sets are accepted and
// discarded, so every write here is followed by a read-back rather than
// trusting the status.
package ms510txup

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client is a client for one switch.
type Client struct {
	endpoint string
	password string

	httpClient *http.Client

	mu       sync.Mutex
	tabid    string
	pub      *rsa.PublicKey
	xsrf     string
	lastCall time.Time
}

// minInterval paces requests. This firmware is older and slower than the
// XS-series and there is no reason to think its management plane is sturdier.
const minInterval = 350 * time.Millisecond

func NewClient(endpoint, password string, _ bool) (*Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}
	return &Client{
		endpoint:   strings.TrimRight(endpoint, "/"),
		password:   password,
		httpClient: &http.Client{Jar: jar, Timeout: 30 * time.Second},
	}, nil
}

const obfuscationAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// obfuscatePassword ports the switch's own encode() from js/utility.js.
//
// The password's characters are placed IN REVERSE at every 7th position of a
// 320-len(pw) character random string, with the password's length encoded as a
// tens digit at index 123 and a ones digit at index 289. It is obfuscation,
// not encryption - it protects nothing - but it has to be reproduced exactly.
//
// math/rand is deliberate: this is padding the server discards, not a secret,
// and using crypto/rand here would imply a security property that does not
// exist.
func obfuscatePassword(password string) string {
	out := make([]byte, 0, 320)
	remaining := len(password)
	total := len(password)
	for i := 1; i <= 320-len(password); i++ {
		switch {
		case i%7 == 0 && remaining > 0:
			remaining--
			out = append(out, password[remaining])
		case i == 123:
			if total < 10 {
				out = append(out, '0')
			} else {
				out = append(out, byte('0'+total/10))
			}
		case i == 289:
			out = append(out, byte('0'+total%10))
		default:
			out = append(out, obfuscationAlphabet[mrand.Intn(len(obfuscationAlphabet))])
		}
	}
	return string(out)
}

// sign ports urlParamHash(): append &bj4=md5(querystring).
func sign(u string) string {
	i := strings.Index(u, "?")
	if i < 0 {
		return u
	}
	sum := md5.Sum([]byte(u[i+1:]))
	return u + "&bj4=" + hex.EncodeToString(sum[:])
}

func (c *Client) url(path string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return sign(fmt.Sprintf("%s/%s%sdummy=%d", c.endpoint, path, sep, time.Now().UnixMilli()))
}

// csrfHeader builds X-CSRF-XSID for the current session. Callers hold c.mu.
func (c *Client) csrfHeader() (string, error) {
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, c.pub, []byte(c.tabid))
	if err != nil {
		return "", fmt.Errorf("encrypt session id: %w", err)
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

// do issues one request. Callers hold c.mu.
func (c *Client) do(path string, body string, hasBody bool) ([]byte, error) {
	if d := time.Until(c.lastCall.Add(minInterval)); d > 0 {
		time.Sleep(d)
	}
	defer func() { c.lastCall = time.Now() }()

	method := http.MethodGet
	var rdr io.Reader
	if hasBody {
		method = http.MethodPost
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, c.url(path), rdr)
	if err != nil {
		return nil, err
	}
	if hasBody {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if c.tabid != "" && c.pub != nil {
		h, err := c.csrfHeader()
		if err != nil {
			return nil, err
		}
		req.Header.Set("X-CSRF-XSID", h)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s returned 404. On this switch that means the request was not "+
			"authorised - the X-CSRF-XSID header was missing, wrong, or the session expired - far more "+
			"often than it means the command does not exist", path)
	}
	if resp.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("%s returned 400, which on this switch means the bj4 URL signature "+
			"was missing or did not match", path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %d: %.200s", path, resp.StatusCode, raw)
	}
	return raw, nil
}

// Field is one form field. Writes use an ordered slice rather than a map
// because this CGI is order-sensitive: the login form in particular must send
// pwd before actKeyText, and Go's url.Values.Encode() sorts keys
// alphabetically, which silently reorders them and fails as a bad password.
type Field struct {
	Key   string
	Value string
}

func encodeFields(fields []Field) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		parts = append(parts, url.QueryEscape(f.Key)+"="+url.QueryEscape(f.Value))
	}
	return strings.Join(parts, "&")
}

type loginAuthReply struct {
	Status string `json:"status"`
	AuthID string `json:"authId"`
	Msg    string `json:"msg"`
}

type loginStatusReply struct {
	Data struct {
		Status     string `json:"status"`
		Sess       string `json:"sess"`
		FailReason string `json:"failReason"`
	} `json:"data"`
}

// parseSess splits the login blob into the session id and the public key.
func parseSess(sessB64 string) (string, *rsa.PublicKey, error) {
	// The blob is padded with a trailing NUL that base64 round-trips.
	raw, err := base64.StdEncoding.DecodeString(sessB64)
	if err != nil {
		return "", nil, fmt.Errorf("decode session blob: %w", err)
	}
	s := strings.TrimRight(string(raw), "\x00")
	if len(s) < 38 {
		return "", nil, fmt.Errorf("session blob is too short to hold a key (%d bytes)", len(s))
	}
	tabid := s[0:32]
	expo, ok := new(big.Int).SetString(s[32:37], 16)
	if !ok {
		return "", nil, fmt.Errorf("could not parse the public exponent %q", s[32:37])
	}
	modulus, ok := new(big.Int).SetString(s[37:], 16)
	if !ok {
		return "", nil, fmt.Errorf("could not parse the modulus")
	}
	return tabid, &rsa.PublicKey{N: modulus, E: int(expo.Int64())}, nil
}

// login runs the full handshake. Callers hold c.mu.
func (c *Client) login() error {
	c.tabid, c.pub, c.xsrf = "", nil, ""

	// Touch the login page first, as the UI does.
	if _, err := c.do(fmt.Sprintf("login.html?aj4=%d", time.Now().UnixMilli()), "", false); err != nil {
		return fmt.Errorf("load login page: %w", err)
	}

	body := encodeFields([]Field{{"pwd", obfuscatePassword(c.password)}, {"actKeyText", ""}})
	raw, err := c.do("cgi/set.cgi?cmd=home_loginAuth", body, true)
	if err != nil {
		return fmt.Errorf("loginAuth: %w", err)
	}
	var auth loginAuthReply
	if err := json.Unmarshal(raw, &auth); err != nil {
		return fmt.Errorf("decode loginAuth reply: %w (body %.200s)", err, raw)
	}
	if auth.Status != "ok" || auth.AuthID == "" {
		return fmt.Errorf("loginAuth rejected: status %q %s", auth.Status, auth.Msg)
	}

	// Poll until authentication completes. The first poll legitimately fails.
	statusBody := encodeFields([]Field{{"authId", auth.AuthID}})
	for attempt := 0; attempt < 15; attempt++ {
		raw, err := c.do("cgi/set.cgi?cmd=home_loginStatus", statusBody, true)
		if err != nil {
			return fmt.Errorf("loginStatus: %w", err)
		}
		var st loginStatusReply
		if err := json.Unmarshal(raw, &st); err != nil {
			return fmt.Errorf("decode loginStatus reply: %w (body %.200s)", err, raw)
		}
		switch st.Data.Status {
		case "ok":
			if st.Data.Sess == "" {
				return fmt.Errorf("login reported ok but returned no session blob")
			}
			c.tabid, c.pub, err = parseSess(st.Data.Sess)
			return err
		case "fail":
			return fmt.Errorf("login failed: %s", st.Data.FailReason)
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("login never completed")
}

// ensure establishes a session if there is not one. Callers hold c.mu.
func (c *Client) ensure() error {
	if c.tabid != "" && c.pub != nil {
		return nil
	}
	return c.login()
}

// envelope is the shape every CGI reply shares.
type envelope struct {
	Data   json.RawMessage `json:"data"`
	Xsrf   string          `json:"xsrf"`
	Status string          `json:"status"`
	Logout any             `json:"logout"`
	Reason string          `json:"reason"`
}

// Get reads one command, decoding its `data` field into out.
func (c *Client) Get(cmd string, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getLocked(cmd, out)
}

func (c *Client) getLocked(cmd string, out any) error {
	if err := c.ensure(); err != nil {
		return err
	}
	raw, err := c.do("cgi/get.cgi?cmd="+cmd, "", false)
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decode %s reply: %w (body %.200s)", cmd, err, raw)
	}
	if env.Xsrf != "" {
		c.xsrf = env.Xsrf
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Data, out)
}

// refreshXsrf fetches the write token. Callers hold c.mu.
func (c *Client) refreshXsrf() error {
	var home struct {
		Xsrf string `json:"xsrf"`
	}
	if err := c.getLocked("home_home", &home); err != nil {
		return err
	}
	if home.Xsrf == "" {
		return fmt.Errorf("home_home returned no xsrf token")
	}
	c.xsrf = home.Xsrf
	return nil
}

// Set posts a write.
//
// The reply status is NOT proof the write took: this firmware answers
// save_success for field sets it silently discarded. Callers must read back.
func (c *Client) Set(cmd string, fields []Field) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensure(); err != nil {
		return err
	}
	if c.xsrf == "" {
		if err := c.refreshXsrf(); err != nil {
			return err
		}
	}

	body := "_ds=1&"
	if encoded := encodeFields(fields); encoded != "" {
		body += encoded
	} else {
		body += "empty=1"
	}
	body += "&xsrf=" + c.xsrf + "&_de=1"

	raw, err := c.do("cgi/set.cgi?cmd="+cmd, body, true)
	if err != nil {
		return err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("decode %s reply: %w (body %.200s)", cmd, err, raw)
	}
	if env.Xsrf != "" {
		c.xsrf = env.Xsrf
	}
	if env.Logout != nil {
		c.tabid, c.pub, c.xsrf = "", nil, ""
		return fmt.Errorf("%s was rejected and the session was dropped (reason %q)", cmd, env.Reason)
	}
	if env.Status != "" && env.Status != "ok" {
		return fmt.Errorf("%s returned status %q", cmd, env.Status)
	}
	return nil
}

// --- syslog -----------------------------------------------------------------

// SyslogHost is one remote collector.
type SyslogHost struct {
	Type int    `json:"type"` // 0 IPv4, 1 IPv6, 2 hostname
	Host string `json:"host"`
	Port int    `json:"port"`
	Sev  int    `json:"sev"`
	// Status arrives as an untranslated lang() key rather than a value, e.g.
	// "lang('log','txtActive')". It is a UI string, not state worth parsing.
	Status string `json:"status"`
}

// SyslogConfig is the switch's remote logging state.
type SyslogConfig struct {
	State int          `json:"state"`
	Hosts []SyslogHost `json:"hosts"`
}

func (c *Client) GetSyslog() (SyslogConfig, error) {
	var cfg SyslogConfig
	err := c.Get("log_remote", &cfg)
	return cfg, err
}

// SetSyslogState turns remote logging on or off switch-wide. Host entries are
// inert without it.
func (c *Client) SetSyslogState(on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	return c.Set("log_remote", []Field{{"state", v}})
}

func (c *Client) AddSyslogHost(h SyslogHost) error {
	return c.Set("log_remoteAdd", []Field{
		{"type", fmt.Sprint(h.Type)}, {"host", h.Host},
		{"port", fmt.Sprint(h.Port)}, {"sev", fmt.Sprint(h.Sev)},
	})
}

// DeleteSyslogHost removes a collector. The UI's delete posts the selected
// row's key as selEntry.
func (c *Client) DeleteSyslogHost(host string) error {
	return c.Set("log_remoteDel", []Field{{"selEntry", host}})
}

func (c *Client) FindSyslogHost(host string) (*SyslogHost, error) {
	cfg, err := c.GetSyslog()
	if err != nil {
		return nil, err
	}
	for i := range cfg.Hosts {
		if cfg.Hosts[i].Host == host {
			return &cfg.Hosts[i], nil
		}
	}
	return nil, nil
}

// --- time -------------------------------------------------------------------

// TimeConfig is the clock configuration. Type 0 is a manually set clock, 1 is
// SNTP.
type TimeConfig struct {
	Type     int    `json:"type"`
	Time     int64  `json:"time"`
	TzName   string `json:"tzName"`
	TzDiff   int    `json:"tzDiff"` // minutes east of UTC
	SntpMode int    `json:"sntpMode"`
}

func (c *Client) GetTime() (TimeConfig, error) {
	var t TimeConfig
	err := c.Get("time_time", &t)
	return t, err
}

// SNTP client modes, from the radio group in sys_mgmt_time.html:
//
//	RadioGroup('sntpMode', data.sntpMode, [0, Unicast], [1, Broadcast])
//
// The ordering is worth stating because the obvious guess is wrong and the
// failure is silent. In BROADCAST mode the client waits passively for NTP
// broadcasts and never transmits, so `reqs` stays 0 forever and the switch
// looks like it has a broken SNTP client - "SNTP is Enabled" in the CLI, a
// server configured, no requests, no error. It is doing exactly what it was
// told.
const (
	SNTPUnicast   = 0
	SNTPBroadcast = 1
)

// SetSNTP switches the clock to SNTP unicast and sets the timezone.
//
// The whole form has to be sent. A partial write is accepted, reported as
// save_success, and discarded - sending only type and sntpMode changes
// nothing at all.
func (c *Client) SetSNTP(tzName string, tzHours, tzMinutes int) error {
	return c.Set("time_time", []Field{
		{"type", "1"}, {"sntpMode", fmt.Sprint(SNTPUnicast)}, {"sntpPort", "123"}, {"ver", "4"},
		{"uniPollInterval", "6"}, {"broadcastPollInterval", "6"},
		{"uniPollTimeout", "5"}, {"uniPollRetry", "1"},
		{"tzName", tzName}, {"tzHours", fmt.Sprint(tzHours)}, {"tzMin", fmt.Sprint(tzMinutes)},
		{"date", ""}, {"time", ""},
	})
}

// SNTPServer is one configured time source.
type SNTPServer struct {
	Type int    `json:"type"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Pri  int    `json:"pri"`
	Ver  int    `json:"ver"`
}

type sntpConfig struct {
	Servers []SNTPServer `json:"servers"`
}

func (c *Client) ListSNTPServers() ([]SNTPServer, error) {
	var cfg sntpConfig
	err := c.Get("time_sntp", &cfg)
	return cfg.Servers, err
}

// AddSNTPServer adds a time source. Note the field is `ip`, not `addr`; the
// switch accepts `addr` and silently discards the whole entry.
func (c *Client) AddSNTPServer(s SNTPServer) error {
	return c.Set("time_sntpAdd", []Field{
		{"type", fmt.Sprint(s.Type)}, {"ip", s.IP},
		{"port", fmt.Sprint(s.Port)}, {"pri", fmt.Sprint(s.Pri)}, {"ver", fmt.Sprint(s.Ver)},
	})
}

// DeleteSNTPServer removes a time source. The row key is its priority.
func (c *Client) DeleteSNTPServer(pri int) error {
	return c.Set("time_sntpDel", []Field{{"selEntry", fmt.Sprint(pri)}})
}

// --- misc -------------------------------------------------------------------

// DNSConfig is the switch's resolver configuration.
type DNSConfig struct {
	State int `json:"state"`
	DNS   []struct {
		IP   string `json:"ip"`
		Pref int    `json:"pref"`
		Idx  int    `json:"idx"`
	} `json:"dnss"`
}

func (c *Client) GetDNS() (DNSConfig, error) {
	var d DNSConfig
	err := c.Get("sys_dnsConf", &d)
	return d, err
}

// SysInfo is the identity and uptime block.
type SysInfo struct {
	SysName     string `json:"sysName"`
	SysSN       string `json:"sysSN"`
	SysDateTime string `json:"sysDateTime"`
	UpTimeDays  int    `json:"sysUpTimeDays"`
}

func (c *Client) GetSysInfo() (SysInfo, error) {
	var s SysInfo
	err := c.Get("sys_info", &s)
	return s, err
}

// Logout releases the session.
func (c *Client) Logout() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tabid == "" {
		return nil
	}
	_, err := c.do("cgi/set.cgi?cmd=home_logout", "", true)
	c.tabid, c.pub, c.xsrf = "", nil, ""
	return err
}
