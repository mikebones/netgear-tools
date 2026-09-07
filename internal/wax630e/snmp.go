package wax630e

// SNMPv1v2c is the community-string half of the SNMP configuration.
//
// NEW IN FIRMWARE 12.8.0.6. Earlier releases expose SNMPv3 only, so on an AP
// that has not been upgraded this whole subtree does not exist and the query
// fails rather than returning it empty.
type SNMPv1v2c struct {
	Status                      string `json:"status"`
	ReadOnlyCommunity           string `json:"readOnlyCommunity"`
	UseReadOnlyCommunityForTrap string `json:"useReadOnlyCommunityForTrap"`
	TrapCommunity               string `json:"trapCommunity"`
}

// SNMPv3User is one v3 identity - the polling user, or the trap user.
type SNMPv3User struct {
	UserName       string `json:"userName"`
	SecurityLevel  string `json:"securityLevel"`
	AuthProtocol   string `json:"authProtocol"`
	AuthPassphrase string `json:"authPassphrase,omitempty"`
	PrivProtocol   string `json:"privProtocol"`
	PrivPassphrase string `json:"privPassphrase,omitempty"`
}

// SNMPv3 is the user-based half of the SNMP configuration.
type SNMPv3 struct {
	Status             string     `json:"status"`
	UserName           string     `json:"userName"`
	SecurityLevel      string     `json:"securityLevel"`
	AuthProtocol       string     `json:"authProtocol"`
	AuthPassphrase     string     `json:"authPassphrase,omitempty"`
	PrivProtocol       string     `json:"privProtocol"`
	PrivPassphrase     string     `json:"privPassphrase,omitempty"`
	UseSameUserForTrap string     `json:"useSameUserForTrap"`
	TrapUser           SNMPv3User `json:"trapUser"`
}

// SNMPTrapTarget is where traps are sent.
type SNMPTrapTarget struct {
	TrapServerIP string `json:"trapServerIP"`
	TrapPort     string `json:"trapPort"`
}

// SNMPSettings is the AP's whole SNMP configuration.
//
// WORTH DECLARING PRECISELY BECAUSE IT IS OFF. This AP ships SNMP disabled but
// fully PRE-POPULATED: community strings "snmpv1v2cuser" and "trapuser", v3
// auth and privacy passphrases both literally "snmp1234" under MD5 and DES,
// and a trap target already aimed at the gateway. None of that is reachable
// while snmpStatus is "0" - but it is what somebody gets the day they enable
// SNMP to collect one metric, and they will not think to change it because
// they never chose it.
//
// So the point of managing this is drift detection, not configuration: a
// declared "off" notices the day it stops being off.
type SNMPSettings struct {
	SNMPStatus string         `json:"snmpStatus"`
	V1V2c      SNMPv1v2c      `json:"snmpV1V2c"`
	V3         SNMPv3         `json:"snmpV3"`
	TrapTarget SNMPTrapTarget `json:"trapTarget"`
}

type snmpEnvelope struct {
	System struct {
		RemoteSettings struct {
			SNMP SNMPSettings `json:"snmp"`
		} `json:"remoteSettings"`
	} `json:"system"`
}

// snmpTemplate is the query-by-example template. Passphrases are asked for
// explicitly, and the AP returns them in CLEAR - worth knowing before the
// result goes anywhere it will be kept.
func snmpTemplate() map[string]any {
	user := func() map[string]any {
		return map[string]any{
			"userName": "", "securityLevel": "", "authProtocol": "",
			"authPassphrase": "", "privProtocol": "", "privPassphrase": "",
		}
	}
	v3 := user()
	v3["status"] = ""
	v3["useSameUserForTrap"] = ""
	v3["trapUser"] = user()
	return map[string]any{
		"snmpStatus": "",
		"snmpV1V2c": map[string]any{
			"status": "", "readOnlyCommunity": "",
			"useReadOnlyCommunityForTrap": "", "trapCommunity": "",
		},
		"snmpV3":     v3,
		"trapTarget": map[string]any{"trapServerIP": "", "trapPort": ""},
	}
}

// GetSNMP returns the AP's SNMP configuration.
//
// CONTAINS SECRETS IN CLEAR: both community strings and both v3 passphrases.
func (c *Client) GetSNMP() (SNMPSettings, error) {
	var out snmpEnvelope
	err := c.Call(map[string]any{"system": map[string]any{
		"remoteSettings": map[string]any{"snmp": snmpTemplate()},
	}}, &out)
	return out.System.RemoteSettings.SNMP, err
}

// SetSNMP writes the AP's SNMP configuration. Read-modify-write: send back
// what GetSNMP returned, with the fields you mean to change.
func (c *Client) SetSNMP(s SNMPSettings) error {
	return c.Call(map[string]any{"system": map[string]any{
		"remoteSettings": map[string]any{"snmp": s},
	}}, nil)
}
