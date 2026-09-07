package pr60x

import "encoding/json"

// SNMPv1v2c holds the community strings.
//
// THE ROUTER SHIPS "public" AND "private". SNMP is disabled out of the box, so
// nothing is exposed - but those are the two community strings every scanner
// on earth tries first, and they are what somebody gets the day they enable
// SNMP to collect one metric. They will not think to change credentials they
// never chose.
type SNMPv1v2c struct {
	CommunityPublic  string `json:"communityPublic"`
	CommunityPrivate string `json:"communityPrivate"`
	// ClientIPAddress restricts which host may poll. Empty means anyone who
	// can reach the router, which with default communities is the whole LAN.
	ClientIPAddress string `json:"clientIpAddress"`
}

// SNMPSettings is the router's SNMP configuration.
type SNMPSettings struct {
	Enabled       int             `json:"enabled"`
	V1V2cEnabled  int             `json:"v1v2cEnabled"`
	V3Enabled     int             `json:"v3Enabled"`
	SysContact    string          `json:"sysContact"`
	SysLocation   string          `json:"sysLocation"`
	SysName       string          `json:"sysName"`
	V1V2cSettings SNMPv1v2c       `json:"v1v2cSettings"`
	V3Settings    json.RawMessage `json:"v3Settings,omitempty"`
}

// UsingDefaultCommunities reports whether the shipped community strings are
// still in place. Named explicitly rather than pattern-matched so the check
// does not quietly stop working when somebody picks something similar.
func (s SNMPSettings) UsingDefaultCommunities() bool {
	return s.V1V2cSettings.CommunityPublic == "public" ||
		s.V1V2cSettings.CommunityPrivate == "private"
}

// GetSNMPSettings returns the router's SNMP configuration.
func (c *Client) GetSNMPSettings() (SNMPSettings, error) {
	var out SNMPSettings
	err := c.CallResult("getSnmpSettings", map[string]any{}, &out)
	return out, err
}

// SetSNMPSettings writes it back. Read-modify-write.
func (c *Client) SetSNMPSettings(s SNMPSettings) error {
	var out json.RawMessage
	return c.CallResult("setSnmpSettings", s, &out)
}

// GUIIdleTimeout is the web session idle timeout, in minutes.
type GUIIdleTimeout struct {
	Minutes int `json:"softIdleTimeoutMinutes"`
}

// GetGUIIdleTimeout returns the web UI idle timeout. Ships at 45 minutes.
func (c *Client) GetGUIIdleTimeout() (GUIIdleTimeout, error) {
	var out GUIIdleTimeout
	err := c.CallResult("getGuiIdleTimeout", map[string]any{}, &out)
	return out, err
}

// SetGUIIdleTimeout writes it.
func (c *Client) SetGUIIdleTimeout(t GUIIdleTimeout) error {
	var out json.RawMessage
	return c.CallResult("setGuiIdleTimeout", t, &out)
}

// PasswordRecovery is the security-question password reset.
//
// Disabled from the factory, and that is the safer setting: enabling it adds
// two security answers as an alternative path to admin, and security questions
// are typically guessable or discoverable rather than secret.
type PasswordRecovery struct {
	Enabled         int    `json:"enabled"`
	SecurityQ1      int    `json:"securityQuestion1"`
	SecurityQ2      int    `json:"securityQuestion2"`
	SecurityAnswer1 string `json:"securityAnswer1,omitempty"`
	SecurityAnswer2 string `json:"securityAnswer2,omitempty"`
}

// GetPasswordRecovery returns the password-recovery configuration.
func (c *Client) GetPasswordRecovery() (PasswordRecovery, error) {
	var out PasswordRecovery
	err := c.CallResult("getPasswordRecovery", map[string]any{}, &out)
	return out, err
}

// LEDControl is the front-panel LED switch: 0 normal, 1 off.
type LEDControl struct {
	LEDControl int `json:"ledControl"`
}

// GetLEDControl returns the LED setting.
func (c *Client) GetLEDControl() (LEDControl, error) {
	var out LEDControl
	err := c.CallResult("getLedControl", map[string]any{}, &out)
	return out, err
}

// SetLEDControl writes it.
func (c *Client) SetLEDControl(l LEDControl) error {
	var out json.RawMessage
	return c.CallResult("setLedControl", l, &out)
}

// LLDPPortSetting is LLDP on one port.
type LLDPPortSetting struct {
	Port    string `json:"port"`
	Enabled int    `json:"enabled"`
}

// LLDPSettings is the router's LLDP configuration.
//
// Worth declaring because LLDP is how a network describes itself. This router
// ships it ON for every LAN port and OFF for wan1 - which is the correct shape
// and easy to get wrong in the dangerous direction: LLDP on the WAN
// broadcasts the router's model, firmware and port names to the ISP segment.
type LLDPSettings struct {
	Enabled      int               `json:"enabled"`
	PortSettings []LLDPPortSetting `json:"portSettings"`
}

// GetLLDPSettings returns the LLDP configuration.
func (c *Client) GetLLDPSettings() (LLDPSettings, error) {
	var out LLDPSettings
	err := c.CallResult("getLldpSettings", map[string]any{}, &out)
	return out, err
}

// SetLLDPSettings writes it back. Send the whole object, ports included.
func (c *Client) SetLLDPSettings(l LLDPSettings) error {
	var out json.RawMessage
	return c.CallResult("setLldpSettings", l, &out)
}

// NTPSettings is the router's clock source.
//
// CustomServerEnable 0 means the vendor pool in ServerIPAddr is used -
// time-b.netgear.com and time-c.netgear.com from the factory. The router is
// the LAN's own time reference for the switches, so where it gets time from
// determines whether the whole network's timestamps agree.
type NTPSettings struct {
	CustomServerEnable int      `json:"customServerEnable"`
	ServerIPAddr       []string `json:"serverIpAddr"`
}

// GetNTPSettings returns the NTP configuration.
func (c *Client) GetNTPSettings() (NTPSettings, error) {
	var out NTPSettings
	err := c.CallResult("getNtpSettings", map[string]any{}, &out)
	return out, err
}

// SetNTPSettings writes it.
func (c *Client) SetNTPSettings(n NTPSettings) error {
	var out json.RawMessage
	return c.CallResult("setNtpSettings", n, &out)
}

// MDNSSettings is the mDNS reflector.
//
// OFF from the factory, and that is a real decision rather than an oversight.
// mDNS is link-local by design - 224.0.0.251 with TTL 1 - so it does not cross
// a VLAN boundary. The reflector is what makes discovery work between VLANs,
// and it is the setting to reach for when a phone on one VLAN cannot see a
// printer or a Chromecast on another. Leaving it off is correct while
// everything that needs to discover each other shares a VLAN.
type MDNSSettings struct {
	EnableReflector int `json:"enableReflector"`
}

// GetMDNSSettings returns the mDNS reflector setting.
func (c *Client) GetMDNSSettings() (MDNSSettings, error) {
	var out MDNSSettings
	err := c.CallResult("getMdnsSettings", map[string]any{}, &out)
	return out, err
}

// SetMDNSSettings writes it.
func (c *Client) SetMDNSSettings(m MDNSSettings) error {
	var out json.RawMessage
	return c.CallResult("setMdnsSettings", m, &out)
}
