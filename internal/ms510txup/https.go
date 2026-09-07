package ms510txup

import "fmt"

// WebAccess is one of the switch's two management listeners, HTTP or HTTPS.
//
// The two are configured by separate commands (`access_http`, `access_https`)
// but share a field set, which is why one type serves both.
type WebAccess struct {
	// Admin is the listener's on/off switch.
	Admin int `json:"admin"`
	// Port applies to HTTPS only; the HTTP listener does not expose one.
	Port int `json:"port,omitempty"`
	// SoftTimeout is idle minutes before a session is dropped (5-60).
	//
	// THIS IS THE SESSION-SLOT LIFETIME, and it matters more than it looks.
	// MaxSess is 4 and the switch frees a slot only after this long, so any
	// tool that exits without logging out burns one for the full duration.
	// Enough of those and every login is refused.
	SoftTimeout int `json:"softTo"`
	// HardTimeout is the absolute session lifetime in hours (1-168).
	HardTimeout int `json:"hardTo"`
	// MaxSessions is capped at 4 by the firmware.
	MaxSessions int `json:"maxSess"`

	// Present is read-only and HTTPS-only: whether a certificate exists.
	// HTTPS cannot be enabled without one.
	Present int `json:"present,omitempty"`
	// SSLv3 and TLSv1 enable those legacy protocol versions. Both ship 0 and
	// should stay 0; they exist for equipment that should not be on a network.
	SSLv3 int `json:"sslv3,omitempty"`
	TLSv1 int `json:"tlsv1,omitempty"`
}

// GetHTTP returns the plain-HTTP listener's configuration.
func (c *Client) GetHTTP() (WebAccess, error) {
	var out WebAccess
	err := c.Get("access_http", &out)
	return out, err
}

// GetHTTPS returns the HTTPS listener's configuration.
func (c *Client) GetHTTPS() (WebAccess, error) {
	var out WebAccess
	err := c.Get("access_https", &out)
	return out, err
}

// SetHTTPS writes the HTTPS listener's configuration.
//
// SEND THE WHOLE ROW. This is the lesson that took longest to learn on this
// switch: a write missing a required field is accepted and silently
// discarded - the reply still says save_success. `admin=1` on its own does
// nothing; admin plus port, softTo, hardTo, maxSess, tlsv1 and sslv3 works.
// Every "this setting is only reachable through the web UI" conclusion on
// this device has so far turned out to be a missing field instead.
//
// HTTPS CANNOT BE ENABLED WITHOUT A CERTIFICATE. Check Present first, and see
// GenerateCertificate.
func (c *Client) SetHTTPS(w WebAccess) error {
	if w.Admin == 1 && w.Present == 0 {
		return fmt.Errorf("cannot enable HTTPS: no certificate present - " +
			"generate one first (System > Protocols > HTTPS in the web UI)")
	}
	return c.Set("access_https", []Field{
		{"admin", fmt.Sprint(w.Admin)},
		{"port", fmt.Sprint(w.Port)},
		{"softTo", fmt.Sprint(w.SoftTimeout)},
		{"hardTo", fmt.Sprint(w.HardTimeout)},
		{"maxSess", fmt.Sprint(w.MaxSessions)},
		{"tlsv1", fmt.Sprint(w.TLSv1)},
		{"sslv3", fmt.Sprint(w.SSLv3)},
	})
}

// CertificateStatus reports whether the switch holds an HTTPS certificate.
type CertificateStatus struct {
	Admin   int `json:"admin"`
	Present int `json:"present"`
	Status  int `json:"status"`
}

// GetCertificate returns the HTTPS certificate status.
func (c *Client) GetCertificate() (CertificateStatus, error) {
	var out CertificateStatus
	err := c.Get("access_httpsCert", &out)
	return out, err
}

// GenerateCertificate asks the switch to create a self-signed certificate.
//
// DOES NOT WORK, AND IS KEPT TO SAY SO. `access_httpsCert` accepts admin=1
// and leaves present at 0 - unlike SetHTTPS, sending more fields does not
// help, because the generation form carries subject details this command has
// no parameters for. Generation is a web-UI job:
//
//	System > Protocols > HTTPS > Certificate > Generate Certificates
//
// Enabling HTTPS afterwards works fine over the API, so this is the only step
// that needs a browser.
//
// The generated certificate has CN=Switch, which satisfies "no plaintext
// password on the wire" and nothing more - it will never validate against a
// hostname. For that, the same page has a Certificate Upload section taking a
// PEM file.
func (c *Client) GenerateCertificate() error {
	return fmt.Errorf("certificate generation is not reachable over this API: " +
		"access_httpsCert accepts the write and discards it, because the UI form " +
		"supplies subject details this command has no fields for. Generate it at " +
		"System > Protocols > HTTPS > Certificate > Generate Certificates, then " +
		"enable HTTPS with SetHTTPS")
}
