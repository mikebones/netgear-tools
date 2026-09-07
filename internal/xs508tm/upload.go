package xs508tm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"time"
)

// lighttpdSpoolPath is where the web server spools an uploaded file. The
// /cgi/v1/file_upload endpoint writes the multipart body here, and the
// subsequent /api/v1/https_cert_upld call imports whatever is at this path.
// It is a fixed, global path - not per-session - so the spool and the import
// need not share a session, though this client does them in one anyway.
const lighttpdSpoolPath = "/tmp/lighttpd/upload.tmp"

// CertFileType is the switch's File Type selector, captured from the upload
// form. The certificate and the key are TWO separate uploads, not two halves
// of one request.
type CertFileType int

const (
	// CertFileServerCert is "X.509 Public Certificate PEM" (leaf + chain).
	CertFileServerCert CertFileType = 1
	// CertFileServerKey is "X.509 Certificate Private Key PEM".
	CertFileServerKey CertFileType = 2
)

// apiResp is the envelope every /api/v1 reply carries. doOnce only checks the
// HTTP status; https_cert_upld returns HTTP 200 with respCode -1 on a failed
// import, so the import path has to read respCode itself.
type apiResp struct {
	Resp struct {
		Status   string `json:"status"`
		RespCode int    `json:"respCode"`
	} `json:"resp"`
}

// UploadCertificate installs a trusted certificate and key, then enables HTTPS.
//
// # How it works (captured from the web UI, 2026-09-07)
//
// Each file is installed with TWO requests, and this method makes four in all:
//
//	POST /cgi/v1/file_upload      multipart, field "file"  -> spools to lighttpdSpoolPath
//	POST /api/v1/https_cert_upld  {"https_cert_upld":{"file":1,"localpath":<spool>}}
//	POST /cgi/v1/file_upload      (the key)
//	POST /api/v1/https_cert_upld  {"https_cert_upld":{"file":2,"localpath":<spool>}}
//
// The file_upload endpoint lives under /cgi/v1, NOT /api/v1 - which is why an
// earlier reading of only the /api surface concluded this could not be
// reproduced. It can.
//
// # Why the ordering is a safety measure, not a preference
//
// Installing the cert and key are separate, each applied immediately, so
// between the two there is a live mismatch: certstatus drops 1 -> 0. If HTTPS
// is ENABLED while that happens, completing the pair makes lighttpd reload and
// it dies outright - HTTP and HTTPS both stop listening, recoverable only over
// SSH. That is exactly what took sw2 down on 2026-09-07.
//
// So this method disables HTTPS FIRST, uploads both files while lighttpd serves
// only HTTP (a mismatch it does not care about), verifies a matching pair
// landed (certstatus 1), and only then restores HTTPS. If the pair does not
// validate it leaves HTTPS DISABLED and returns an error rather than enabling a
// configuration that would wedge the web server. Enabling with a valid pair
// present is safe; it is the mid-upload reload under HTTPS that is not.
//
// certPEM may be a full chain (leaf + intermediates); the switch serves what it
// is given, which is what lets a browser build the trust path.
//
// # The /cgi auth, which is the whole trick
//
// /cgi/v1/file_upload authenticates DIFFERENTLY from /api/v1. The web UI's
// request interceptor sends the token in a "session" header and the login
// session id in an "lhttpdsid" header for /cgi requests - NOT the
// "Authorization: Bearer" that /api uses. Sent the /api way, file_upload answers
// HTTP 200 with body respCode 403 and spools nothing, so the import then fails
// with respCode -1. spoolFileLocked sends the right headers; the import
// (https_cert_upld) is /api and uses Bearer as normal. Verified end to end
// against sw2 on 2026-09-07: a Let's Encrypt cert installed by this method
// validates cleanly.
func (c *Client) UploadCertificate(certPEM, keyPEM []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
	}
	defer c.logoutLocked()

	// Remember the starting web config so HTTPS is restored to how it was.
	var cfgEnv httpConfigEnvelope
	if err := c.do(http.MethodGet, "http_config", nil, &cfgEnv); err != nil {
		return fmt.Errorf("read http_config: %w", err)
	}
	orig := cfgEnv.HTTPConfig

	// SAFETY: HTTPS off before the cert is touched.
	if orig.HTTPSEnable == 1 {
		off := orig
		off.HTTPSEnable = 0
		if err := c.do(http.MethodPost, "http_config", httpConfigEnvelope{HTTPConfig: off}, nil); err != nil {
			return fmt.Errorf("disable HTTPS before upload: %w", err)
		}
	}

	if err := c.spoolAndImportLocked(certPEM, CertFileServerCert); err != nil {
		return err
	}
	if err := c.spoolAndImportLocked(keyPEM, CertFileServerKey); err != nil {
		return err
	}

	// Confirm a matching pair before re-enabling HTTPS.
	var stEnv certStatusEnvelope
	if err := c.do(http.MethodGet, "https_cert_mgmt", nil, &stEnv); err != nil {
		return fmt.Errorf("read cert status after upload: %w", err)
	}
	if stEnv.Cert.CertStatus != 1 {
		return fmt.Errorf("certificate/key pair did not validate after upload "+
			"(certstatus=%d); HTTPS left DISABLED to avoid wedging lighttpd", stEnv.Cert.CertStatus)
	}

	// Restore the original web config (re-enabling HTTPS if it had been on).
	if err := c.do(http.MethodPost, "http_config", httpConfigEnvelope{HTTPConfig: orig}, nil); err != nil {
		return fmt.Errorf("restore http_config after upload: %w", err)
	}
	return nil
}

// spoolAndImportLocked uploads one PEM and imports it as cert(1) or key(2).
// Caller holds c.mu and an authenticated session.
func (c *Client) spoolAndImportLocked(pem []byte, ft CertFileType) error {
	if err := c.spoolFileLocked(pem); err != nil {
		return fmt.Errorf("spool file (type %d): %w", ft, err)
	}
	var out apiResp
	body := map[string]any{"https_cert_upld": map[string]any{
		"file": int(ft), "localpath": lighttpdSpoolPath}}
	if err := c.do(http.MethodPost, "https_cert_upld", body, &out); err != nil {
		return fmt.Errorf("https_cert_upld (type %d): %w", ft, err)
	}
	if out.Resp.Status != "success" || out.Resp.RespCode != 0 {
		return fmt.Errorf("https_cert_upld import (type %d) rejected: status=%q respCode=%d",
			ft, out.Resp.Status, out.Resp.RespCode)
	}
	return nil
}

// spoolFileLocked POSTs one file to /cgi/v1/file_upload as multipart/form-data
// under the field name "file", which lighttpd spools to lighttpdSpoolPath.
// Caller holds c.mu.
func (c *Client) spoolFileLocked(content []byte) error {
	if since := time.Since(c.lastCall); since < minInterval {
		time.Sleep(minInterval - since)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "upload.pem")
	if err != nil {
		return fmt.Errorf("create form file: %w", err)
	}
	if _, err := part.Write(content); err != nil {
		return fmt.Errorf("write form file: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close multipart writer: %w", err)
	}

	// NB: /cgi/v1/, not /api/v1/, and it authenticates DIFFERENTLY from the REST
	// API. The web UI's request interceptor sends the token in a "session"
	// header and the session id in an "lhttpdsid" header for /cgi requests -
	// NOT "Authorization: Bearer", which is /api only. Miss this and the
	// endpoint answers HTTP 200 with respCode 403 and spools nothing. The
	// lhttpdsid value is the session cookie set at login; pull it from the jar.
	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/cgi/v1/file_upload", &buf)
	if err != nil {
		return fmt.Errorf("build file_upload request: %w", err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("session", c.token)
	if sid := c.sessionCookie(); sid != "" {
		req.Header.Set("lhttpdsid", sid)
	}

	resp, err := c.httpClient.Do(req)
	c.lastCall = time.Now()
	if err != nil {
		return fmt.Errorf("file_upload: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Body: truncate(string(raw), 200), Path: "cgi/v1/file_upload"}
	}
	// The endpoint answers HTTP 200 even when it refuses the upload, carrying the
	// verdict in the body's respCode. In particular it returns respCode 403 to
	// every non-browser client tried so far (cookie and/or Bearer, with and
	// without Referer/Origin) - see the note on UploadCertificate. Surface that
	// rather than pressing on to an import that then fails with a vaguer -1.
	var out apiResp
	if len(raw) > 0 && json.Unmarshal(raw, &out) == nil && out.Resp.RespCode != 0 {
		return fmt.Errorf("file_upload rejected: respCode=%d status=%q (the /cgi/v1/file_upload "+
			"endpoint has not been made to accept a non-browser client; install via the web UI)",
			out.Resp.RespCode, out.Resp.Status)
	}
	return nil
}

// sessionCookie returns the value of the lhttpdsid session cookie the switch
// sets at login, read from the client's cookie jar. The /cgi endpoints want it
// echoed back in an "lhttpdsid" request header (see spoolFileLocked).
func (c *Client) sessionCookie() string {
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return ""
	}
	for _, ck := range c.httpClient.Jar.Cookies(u) {
		if ck.Name == "lhttpdsid" {
			return ck.Value
		}
	}
	return ""
}
