package xs508tm

// IPNetworkConfig is the switch's management-interface addressing.
//
// WHY THIS EXISTS. The management IP was the one piece of this switch's
// configuration that lived nowhere but the device itself - not in the client,
// not in Terraform. When a factory reset dropped it (2026-09-07), recovering
// the switch meant hunting for its DHCP lease and reconstructing .3 by hand.
// Capturing it here, and as a Terraform resource, means the desired address is
// documented and drift against it is visible.
//
// Mode is the firmware's protocol enum: 3 is DHCP (confirmed - the value a
// factory-default switch reports). The static/"none" value is what the CLI
// calls `network protocol none`; set the address with the CLI or the UI rather
// than guessing the enum, because a wrong write here strands the management
// interface on a default address.
type IPNetworkConfig struct {
	MgmtVID int    `json:"mgmtVid"`
	Mode    int    `json:"mode"`
	IP      string `json:"ip"`
	Subnet  string `json:"subnet"`
	Gateway string `json:"gw"`
}

type ipNetworkEnvelope struct {
	Cfg IPNetworkConfig `json:"ip_network_cfg"`
}

// GetIPNetworkConfig returns the management-interface addressing.
func (c *Client) GetIPNetworkConfig() (IPNetworkConfig, error) {
	var out ipNetworkEnvelope
	err := c.Get("ip_network_cfg", &out)
	return out.Cfg, err
}

// SetIPNetworkConfig writes it back.
//
// DANGEROUS BY NATURE: this moves the address the management plane answers on.
// Changing it over HTTP/HTTPS drops the very session making the change, and if
// the new address is unreachable from the caller there is no way back over IP.
// The reliable recovery path when that happens is IPv6 link-local over SSH
// (the fe80:: address is independent of the IPv4 config and survives the
// change) - see docs/xs508tm-recovery.md.
//
// Sent as the whole enveloped object, matching the switch's other setters.
func (c *Client) SetIPNetworkConfig(n IPNetworkConfig) error {
	return c.Post("ip_network_cfg", ipNetworkEnvelope{Cfg: n}, nil)
}

// SSHConfig is the SSH management service.
//
// Admin is the on/off switch. A factory-default switch ships with SSH OFF
// (admin 0), which is why enabling it is worth capturing: without it, a switch
// whose web server is wedged has no second way in. Enabling it here is verified
// working - POST admin=1 and port 22 begins listening.
type SSHConfig struct {
	Admin       int `json:"admin"`
	Version     int `json:"version"`
	Port        int `json:"port"`
	SessTimeout int `json:"sessTo"`
	MaxSessions int `json:"maxSess"`
}

type sshConfigEnvelope struct {
	Cfg SSHConfig `json:"ssh_global_cfg"`
}

// GetSSHConfig returns the SSH service configuration.
func (c *Client) GetSSHConfig() (SSHConfig, error) {
	var out sshConfigEnvelope
	err := c.Get("ssh_global_cfg", &out)
	return out.Cfg, err
}

// SetSSHConfig writes it back. Read-modify-write and send the whole object;
// the keys present in a matching pair are how the firmware wants them set,
// which SSH depends on (it needs a host key present - ssh_key_status).
func (c *Client) SetSSHConfig(s SSHConfig) error {
	return c.Post("ssh_global_cfg", sshConfigEnvelope{Cfg: s}, nil)
}

// EnableSSH turns the SSH service on or off, leaving other fields as found.
func (c *Client) EnableSSH(enabled bool) error {
	cur, err := c.GetSSHConfig()
	if err != nil {
		return err
	}
	if enabled {
		cur.Admin = 1
	} else {
		cur.Admin = 0
	}
	return c.SetSSHConfig(cur)
}

// IPRoutingConfig is the switch's L3 routing global state.
//
// admin=1 turns on IPv4 routing. maxNextHops and defTTL are read back and sent
// as found - modelled here only so a write cannot silently clear them.
type IPRoutingConfig struct {
	Admin       int `json:"admin"`
	MaxNextHops int `json:"maxNextHops"`
	DefTTL      int `json:"defTTL"`
}

type ipRoutingEnvelope struct {
	Cfg IPRoutingConfig `json:"ip_routing_cfg"`
}

// GetIPRouting returns the L3 routing configuration.
func (c *Client) GetIPRouting() (IPRoutingConfig, error) {
	var out ipRoutingEnvelope
	err := c.Get("ip_routing_cfg", &out)
	return out.Cfg, err
}

// SetIPRouting writes it back (whole enveloped object).
func (c *Client) SetIPRouting(r IPRoutingConfig) error {
	return c.Post("ip_routing_cfg", ipRoutingEnvelope{Cfg: r}, nil)
}

// EnableIPRouting flips L3 routing on or off, leaving maxNextHops/defTTL as
// found.
func (c *Client) EnableIPRouting(enabled bool) error {
	cur, err := c.GetIPRouting()
	if err != nil {
		return err
	}
	if enabled {
		cur.Admin = 1
	} else {
		cur.Admin = 0
	}
	return c.SetIPRouting(cur)
}

// DHCPRelayGlobal is the DHCP-relay (UDP "ip helper") global state.
// state=1 enables relaying; circuitId is Option-82 handling, sent as found.
type DHCPRelayGlobal struct {
	State     int `json:"state"`
	CircuitID int `json:"circuitId"`
}

type dhcpRelayGlobalEnvelope struct {
	Cfg DHCPRelayGlobal `json:"dhcprelay_global_cfg"`
}

// DHCPRelayServer is one helper address the switch relays DHCP to.
type DHCPRelayServer struct {
	IP string `json:"ip"`
}

type dhcpRelayServersEnvelope struct {
	Servers []DHCPRelayServer `json:"dhcprelay_server_cfg"`
}

// GetDHCPRelayGlobal returns the relay global state.
func (c *Client) GetDHCPRelayGlobal() (DHCPRelayGlobal, error) {
	var out dhcpRelayGlobalEnvelope
	err := c.Get("dhcprelay_global_cfg", &out)
	return out.Cfg, err
}

// SetDHCPRelayGlobal writes the relay global state (whole enveloped object).
func (c *Client) SetDHCPRelayGlobal(g DHCPRelayGlobal) error {
	return c.Post("dhcprelay_global_cfg", dhcpRelayGlobalEnvelope{Cfg: g}, nil)
}

// GetDHCPRelayServers returns the list of helper addresses.
func (c *Client) GetDHCPRelayServers() ([]DHCPRelayServer, error) {
	var out dhcpRelayServersEnvelope
	err := c.Get("dhcprelay_server_cfg", &out)
	return out.Servers, err
}

// SetDHCPRelayServers replaces the whole list of helper addresses.
//
// This is a REPLACE, not an append - the switch takes the complete list, same
// as the syslog server list. Send every address you want to keep.
func (c *Client) SetDHCPRelayServers(servers []DHCPRelayServer) error {
	return c.Post("dhcprelay_server_cfg", dhcpRelayServersEnvelope{Servers: servers}, nil)
}
