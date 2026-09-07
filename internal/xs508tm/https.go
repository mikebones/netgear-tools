package xs508tm

import "fmt"

// HTTPConfig is the XS508TM's web management configuration.
//
// Both listeners live in ONE object here, unlike the MS510TXUP which splits
// them across `access_http` and `access_https`. Same idea, different shape -
// worth knowing when moving between the two switches.
type HTTPConfig struct {
	HTTPEnable  int    `json:"httpEnable"`
	HTTPPort    int    `json:"httpPort"`
	HTTPSEnable int    `json:"httpsEnable"`
	HTTPSPort   int    `json:"httpsPort"`
	SoftTimeout int    `json:"softTimeout"`
	HardTimeout int    `json:"hardTimeout"`
	MaxSessions int    `json:"maxSes"`
	HTTPLang    string `json:"httpLang"`
	ThemeSel    string `json:"themeSel"`
}

type httpConfigEnvelope struct {
	HTTPConfig HTTPConfig `json:"http_config"`
}

// GetHTTPConfig returns the web management configuration.
func (c *Client) GetHTTPConfig() (HTTPConfig, error) {
	var out httpConfigEnvelope
	err := c.Get("http_config", &out)
	return out.HTTPConfig, err
}

// SetHTTPConfig writes it back.
//
// Read-modify-write, and send the whole object: httpLang and themeSel are
// cosmetic but are part of the row, and omitting them is the kind of partial
// write these switches quietly discard.
//
// DISABLING HTTP BREAKS THE EXPORTER. xs508tm-exporter connects over plain
// HTTP, so turning HTTPEnable off means changing its endpoint in the same
// change, not afterwards.
func (c *Client) SetHTTPConfig(h HTTPConfig) error {
	return c.Post("http_config", httpConfigEnvelope{HTTPConfig: h}, nil)
}

// CertStatus reports whether an HTTPS certificate is installed.
//
// This switch ships with one already generated - certstatus 1 straight out of
// the box, dated at manufacture - so unlike the MS510TXUP, enabling HTTPS
// here needs no browser step at all.
type CertStatus struct {
	CertStatus int `json:"certstatus"`
}

type certStatusEnvelope struct {
	Cert CertStatus `json:"https_cert_mgmt"`
}

// GetCertStatus returns the HTTPS certificate status.
func (c *Client) GetCertStatus() (CertStatus, error) {
	var out certStatusEnvelope
	err := c.Get("https_cert_mgmt", &out)
	return out.Cert, err
}

// EnableHTTPS turns on the HTTPS listener, leaving everything else as found.
//
// Refuses when no certificate is installed rather than writing a
// configuration the switch cannot serve.
func (c *Client) EnableHTTPS(enabled bool) error {
	cur, err := c.GetHTTPConfig()
	if err != nil {
		return err
	}
	if enabled {
		st, err := c.GetCertStatus()
		if err != nil {
			return err
		}
		if st.CertStatus == 0 {
			return fmt.Errorf("cannot enable HTTPS: no certificate installed " +
				"(https_cert_mgmt certstatus 0); upload one with https_cert_upld")
		}
		cur.HTTPSEnable = 1
	} else {
		cur.HTTPSEnable = 0
	}
	return c.SetHTTPConfig(cur)
}
