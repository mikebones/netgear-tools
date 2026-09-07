package wax630e

// ManagementSettings is the AP's management plane: who can reach the device
// itself, and how long a session lives.
//
// EVERY FIELD HERE IS A SETTING A FACTORY RESET GETS WRONG IN THE UNSAFE
// DIRECTION, which is the whole reason to declare them. Read from the
// firmware's own /etc/default-config, a reset device comes up with
// cloudStatus 1 - NETGEAR Insight cloud management ENABLED - and dayZero
// provisioning armed. Nothing warns you; the AP simply starts trying to reach
// a vendor cloud service it was deliberately kept away from.
type ManagementSettings struct {
	// CloudStatus is NETGEAR Insight cloud management. "0" is local-only
	// management; "1" hands the AP to NETGEAR's cloud. THE FACTORY DEFAULT IS
	// "1". This device runs "0", so this is a real deviation and the single
	// most important field in this struct.
	CloudStatus string `json:"cloudStatus,omitempty"`
	// CloudConnectivityUI only controls whether the cloud option is offered in
	// the web UI. It does not enable anything on its own.
	CloudConnectivityUI string `json:"cloudConnectivityUI,omitempty"`

	// SpanTreeStatus is the AP's own spanning tree participation.
	//
	// NOT COSMETIC ON THIS NETWORK. A WAX630E running firmware older than
	// 11.8.0.9 sends STP frames with an incorrect Forward Delay that crashes
	// the switch it plugs into - see the 11.8.0.9 release notes. The switch
	// side is defended independently by disabling STP on the AP's port, which
	// is the stronger fix because it does not depend on the AP behaving. This
	// is the other half.
	SpanTreeStatus string `json:"spanTreeStatus,omitempty"`

	// DayZeroStatus is the out-of-box provisioning wizard. "1" on a fresh or
	// reset device, "0" once it has been set up.
	DayZeroStatus string `json:"dayZeroStatus,omitempty"`

	// APName is the device's own name, and it is what identifies this AP in
	// syslog and in the exporter's info metric.
	APName string `json:"apName,omitempty"`
}

// RemoteAccess is the remote-management half: SSH, Telnet, and the web
// session idle timeout.
type RemoteAccess struct {
	// SSHStatus and TelnetStatus are both "0" from the factory and should stay
	// that way. Telnet in particular is plaintext, and there is nothing on
	// this AP that needs a shell.
	SSHStatus    string `json:"sshStatus,omitempty"`
	TelnetStatus string `json:"telnetStatus,omitempty"`

	// InactivityTimeOut is the web session idle timeout in SECONDS, default
	// "300".
	//
	// Worth knowing because of how this AP fails: it caps concurrent logins
	// and frees a slot only when the session goes idle for this long. A tool
	// that exits without logging out - anything calling log.Fatal, which skips
	// deferred calls - burns a slot for this many seconds. Raising this makes
	// that failure mode dramatically worse; lowering it is a reasonable
	// defence.
	InactivityTimeOut string `json:"inactivityTimeOut,omitempty"`
}

// TimeSettings is the clock: timezone and NTP.
//
// The clock matters more than it looks. Every syslog line this AP ships to the
// cluster's Alloy receiver is stamped with it, so a reset AP silently
// backdating or shifting its logs by hours is a debugging trap rather than an
// outage.
type TimeSettings struct {
	// TimeZone is an opaque index into the AP's own table, not an offset and
	// not an IANA name. THE FACTORY DEFAULT IS "93" AND THIS DEVICE RUNS
	// "260", so a reset silently moves the clock. Read the live value; do not
	// try to derive it.
	TimeZone       string `json:"timeZone,omitempty"`
	DaylightSaving string `json:"daylightSaving,omitempty"`

	// NTPClientStatus enables time sync at all.
	NTPClientStatus string `json:"ntpClientStatus,omitempty"`
	// CustomNTPServer is "0" to use the vendor pool named in NTPAddr, "1" to
	// use one of your own.
	CustomNTPServer string `json:"customNtpServer,omitempty"`
	// NTPAddr defaults to time-b.netgear.com, which means the AP reaches out
	// to the vendor for time.
	NTPAddr     string `json:"ntpAddr,omitempty"`
	NTPAddrType string `json:"ntpAddrType,omitempty"`
}

type mgmtEnvelope struct {
	System struct {
		BasicSettings  ManagementSettings `json:"basicSettings"`
		RemoteSettings RemoteAccess       `json:"remoteSettings"`
		TimeSettings   TimeSettings       `json:"timeSettings"`
	} `json:"system"`
}

// GetManagement returns the cloud/STP/dayZero half of basicSettings.
func (c *Client) GetManagement() (ManagementSettings, error) {
	var out mgmtEnvelope
	err := c.Call(map[string]any{"system": map[string]any{
		"basicSettings": map[string]any{
			"cloudStatus": "", "cloudConnectivityUI": "", "spanTreeStatus": "",
			"dayZeroStatus": "", "apName": "",
		},
	}}, &out)
	return out.System.BasicSettings, err
}

// SetManagement writes it back. Read-modify-write.
//
// basicSettings also holds the AP's IP configuration, which SetNetwork owns.
// This sends only the management fields, and the AP leaves the rest alone -
// verified by reading the address back unchanged after a write here.
func (c *Client) SetManagement(m ManagementSettings) error {
	return c.Call(map[string]any{"system": map[string]any{"basicSettings": m}}, nil)
}

// GetRemoteAccess returns SSH, Telnet and the session idle timeout.
func (c *Client) GetRemoteAccess() (RemoteAccess, error) {
	var out mgmtEnvelope
	err := c.Call(map[string]any{"system": map[string]any{
		"remoteSettings": map[string]any{
			"sshStatus": "", "telnetStatus": "", "inactivityTimeOut": "",
		},
	}}, &out)
	return out.System.RemoteSettings, err
}

// SetRemoteAccess writes them back.
//
// remoteSettings also holds the whole SNMP subtree, which SetSNMP owns. As
// with SetManagement, sending only these fields leaves SNMP untouched.
func (c *Client) SetRemoteAccess(r RemoteAccess) error {
	return c.Call(map[string]any{"system": map[string]any{"remoteSettings": r}}, nil)
}

// GetTime returns the clock and NTP configuration.
func (c *Client) GetTime() (TimeSettings, error) {
	var out mgmtEnvelope
	err := c.Call(map[string]any{"system": map[string]any{
		"timeSettings": map[string]any{
			"timeZone": "", "daylightSaving": "", "ntpClientStatus": "",
			"customNtpServer": "", "ntpAddr": "", "ntpAddrType": "",
		},
	}}, &out)
	return out.System.TimeSettings, err
}

// SetTime writes the clock and NTP configuration.
func (c *Client) SetTime(t TimeSettings) error {
	return c.Call(map[string]any{"system": map[string]any{"timeSettings": t}}, nil)
}
