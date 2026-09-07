package xs508tm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

// UploadFile is one part of a multipart upload: the form field name, the
// filename the device sees, and the bytes.
type UploadFile struct {
	Field    string
	Filename string
	Content  []byte
}

// PostMultipart sends a multipart/form-data request to an /api/v1/ route.
//
// WHY THIS EXISTS SEPARATELY FROM Post. Post marshals JSON; some NETGEAR
// upload endpoints are HTML file forms and need real multipart encoding.
// This is that transport, and it is verified working - the switch parses the
// request and answers, rather than rejecting it at the wire level.
//
// NOTE IT IS NOT WHAT https_cert_upld WANTS. See UploadCertificate: that
// route turns out to parse its body as JSON. This machinery is kept because
// the MS510TXUP's certificate upload IS an HTML file form, and because
// proving the encoding was how the JSON finding surfaced.
//
// Fields are ordinary form values; files are file parts. Both are written in
// the order given, because some firmware parsers care and none of them
// document it.
func (c *Client) PostMultipart(path string, fields map[string]string, files []UploadFile, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
	}
	// Same reasoning as Post: hand the session back rather than leaving it for
	// the idle timeout to reap.
	defer c.logoutLocked()

	err := c.doMultipart(path, fields, files, out)
	if isAuthError(err) {
		if lerr := c.login(); lerr != nil {
			return lerr
		}
		err = c.doMultipart(path, fields, files, out)
	}
	return err
}

// doMultipart builds and sends the request. NOT retried on transient errors,
// unlike the JSON path: an upload that half-applied and then gets replayed is
// a worse outcome than one that fails and is retried deliberately.
func (c *Client) doMultipart(path string, fields map[string]string, files []UploadFile, out any) error {
	if since := time.Since(c.lastCall); since < minInterval {
		time.Sleep(minInterval - since)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return fmt.Errorf("write field %s: %w", k, err)
		}
	}
	for _, f := range files {
		part, err := w.CreateFormFile(f.Field, f.Filename)
		if err != nil {
			return fmt.Errorf("create part %s: %w", f.Field, err)
		}
		if _, err := part.Write(f.Content); err != nil {
			return fmt.Errorf("write part %s: %w", f.Field, err)
		}
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close multipart writer: %w", err)
	}

	url := c.endpoint + "/api/v1/" + path
	req, err := http.NewRequest(http.MethodPost, url, &buf)
	if err != nil {
		return fmt.Errorf("build upload request %s: %w", path, err)
	}
	// FormDataContentType carries the boundary; setting Content-Type by hand
	// without it produces a request the device cannot parse and reports as a
	// generic failure.
	req.Header.Set("Content-Type", w.FormDataContentType())
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	c.lastCall = time.Now()
	if err != nil {
		return fmt.Errorf("upload %s: %w", path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read upload reply %s: %w", path, err)
	}
	if resp.StatusCode >= 300 {
		return &APIError{Status: resp.StatusCode, Body: truncate(string(raw), 200), Path: path}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode upload reply %s: %w (body: %s)",
				path, err, truncate(string(raw), 160))
		}
	}
	return nil
}

// CertFileType is the switch's own File Type selector, captured from the
// upload form. THESE ARE TWO SEPARATE UPLOADS, not two halves of one request,
// and that distinction is the whole story - see UploadCertificate.
type CertFileType int

const (
	// CertFileServerCert is "X.509 Public Certificate PEM".
	CertFileServerCert CertFileType = 1
	// CertFileServerKey is "X.509 Certificate Private Key PEM".
	CertFileServerKey CertFileType = 2
)

// UploadCertificate is DELIBERATELY NOT IMPLEMENTED. Read this before trying
// to implement it: doing it wrong takes the switch's entire management
// interface off the network. It did, on 2026-09-07, and only SSH got it back.
//
// # The captured request
//
// Nothing carries the file. The JSON names a path lighttpd has ALREADY spooled
// the upload to:
//
//	POST /api/v1/https_cert_upld   Content-Type: application/json
//	{"https_cert_upld":{"file":1,"localpath":"/tmp/lighttpd/upload.tmp"}}
//
// `file` is the CertFileType. `localpath` is lighttpd's own spool file. The
// browser's form POST is handled by the WEB SERVER, and this JSON call is only
// the "now import what you just spooled" half. NO SINGLE REQUEST FROM A GO
// CLIENT CAN REPRODUCE IT - not JSON, not multipart. That is why every guessed
// JSON body returned respCode -99, and why multipart returned
// "400: Failed to parse json data".
//
// # Why it is not worth finishing
//
// Certificate and key are SEPARATE uploads (file:1 then file:2) and the switch
// applies each immediately. Uploading the certificate alone replaces the
// stored pair and leaves no matching key: https_cert_mgmt goes certstatus
// 1 -> 0 while the RUNNING lighttpd carries on serving the old certificate
// from memory. Nothing looks wrong yet.
//
// The failure lands later and hard. Uploading the key to complete the pair
// killed lighttpd outright - HTTP and HTTPS both stopped listening, and did
// not return from `application stop/start lighttpdMon` or a full `reload`.
// Only port 22 survived.
//
// # If the management interface is already down
//
// SSH is the way back in, and is worth enabling BEFORE touching certificates.
// The CLI cannot repair this state: there is no crypto, certificate or ssl
// command anywhere in it; `ip http` offers only accounting and authentication;
// and `copy <url>` installs ca-root, client-ssl-cert, root-ca-certs and SSH
// keys but has NO destination for the web server's own certificate.
// `clear config` - a full factory reset that also drops the management IP - is
// the only reset the CLI offers.
//
// # Doing it safely, if you must
//
// Through the web UI, in this order, with SSH already enabled:
//
//  1. Disable HTTPS first. The Certificate Management radios are greyed out
//     while HTTPS is on, and an Apply with HTTPS enabled and no valid pair
//     raises "Failed to enable HTTPS admin mode as certificate does not exist"
//     - a modal that then silently swallows every subsequent click.
//  2. Upload the certificate (File Type 1).
//  3. Upload the key (File Type 2).
//  4. Re-enable HTTPS.
//
// Step 3 is the one that killed it here. Have console access ready.
func (c *Client) UploadCertificate(certPEM, keyPEM []byte) error {
	return fmt.Errorf("https_cert_upld cannot be driven from this client: lighttpd spools the file " +
		"and the JSON call only references its temp path, so no single request reproduces it. " +
		"Uploading certificate and key as separate steps has been observed to kill this switch's " +
		"web server outright, recoverable only over SSH - read the doc comment first")
}
