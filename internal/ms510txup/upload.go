package ms510txup

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"
	"time"
)

// Certificate install is TWO multipart uploads to TWO endpoints, then an APPLY.
//
// Captured from the switch's own UI (home/web/html/maintain_download_http.html,
// firmware V1.1.1.11). The upload form POSTs multipart/form-data with three
// fields and one header:
//
//	fileType   "7" (certificate) or "8" (private key)
//	xsrf       the write token (_top.xsrfId, same token set.cgi uses)
//	fileName   the file, sent under the field name "fileName"
//	header     X-CSRF-XSID: encryptStr(tabid)
//
// and the endpoint alone decides which on-box file is written:
//
//	fileType 7 -> POST /cgi/httprootcert.cgi   -> validated `openssl x509`, writes ssl_cert.pem
//	fileType 8 -> POST /cgi/httpservercert.cgi -> validated `openssl rsa -check`, writes ssl_key.pem
//
// TWO headers gate these uploads, and BOTH are required:
//
//  1. X-CSRF-XSID - and this is NOT new code: it is exactly csrfHeader(),
//     base64(RSA-PKCS1v15(tabid, pubkey)), the same value this client already
//     puts on every get.cgi/set.cgi call, computed from the tabid and 1024-bit
//     modulus (public exponent 0x10001) the login handshake returned in its
//     `sess` blob (see parseSess). The switch's home.html builds the identical
//     value with _top.encryptStr(_top.tabid) - and _top.tabid is sess[0:32],
//     _top.modulus is sess[37:], the very fields parseSess already extracts, so
//     the "fetch get.cgi?cmd=home_modulus / read <meta name=\"tabid\">" the UI
//     JS also offers would only re-derive values this client already holds.
//
//  2. Referer - THIS is what earlier headless attempts were missing, and why
//     they 404'd. The upload CGIs (unlike get.cgi/set.cgi) sit behind an
//     anti-CSRF Referer check: a POST with a correct X-CSRF-XSID but NO Referer
//     is answered 404 - the switch's generic "not authorised" 404, identical to
//     a wrong CSRF header - which is exactly what made this look like an RSA
//     problem for so long. Isolated by probing the live switch 2026-09-08: the
//     identical multipart POST returns 404 without a Referer and HTTP 200 with
//     `Referer: <endpoint>/`. Only the host has to match; Origin is not checked.
//
// Unlike every other call in this package, these two POSTs go to the RAW /cgi
// path with NO &dummy= cache-buster and NO &bj4= URL signature - the UI does not
// sign them, and adding a signature is not required (the two headers are the
// authenticators here). c.do() and c.url() are therefore bypassed for the
// upload itself; the status read-back still goes through the normal signed
// get.cgi.
const (
	certFileType = 7 // -> /cgi/httprootcert.cgi   (ssl_cert.pem; leaf + chain)
	keyFileType  = 8 // -> /cgi/httpservercert.cgi (ssl_key.pem; RSA private key only)
)

// UploadCertificate installs a trusted certificate and key on the switch and
// makes them take effect, headlessly.
//
// It performs the two multipart uploads, waits for each to report success, then
// APPLIES the change. Applying is not automatic: the upload CGIs only overwrite
// ssl_cert.pem / ssl_key.pem; the file lighttpd actually serves
// (lighttpd_ssl.pem = ssl_cert.pem + ssl_key.pem) is rebuilt by bin/polld only
// on an HTTPS admin-enable edge. So this drives the "Allow HTTPS" admin flag
// off then on, which triggers polld to rebuild the combined PEM and restart
// lighttpd. Until that edge, port 443 keeps serving the OLD certificate.
//
// certPEM may be a full chain (leaf + intermediates) - the switch cats the file
// verbatim into what it serves, which is what lets a browser build the trust
// path. keyPEM must be an RSA private key: httpservercert.cgi validates it with
// `openssl rsa -check` and rejects an EC/ECDSA key (see the package memo).
//
// The switch caps concurrent logins at four and frees a slot only on idle
// timeout, so this logs out when done rather than stranding a slot.
func (c *Client) UploadCertificate(certPEM, keyPEM []byte) error {
	// Phase 1: spool both files. Needs a live session, the write token, and the
	// X-CSRF-XSID header - all under the lock, none of which the public
	// GetHTTPS/SetHTTPS below may re-enter, so the lock is scoped to here.
	if err := c.uploadCertFiles(certPEM, keyPEM); err != nil {
		return err
	}

	// Phase 2: APPLY. Read the whole HTTPS row back (this switch discards a
	// partial write), confirm a certificate is present, then force an
	// enable-edge by driving admin off then on so polld rebuilds and reloads.
	https, err := c.GetHTTPS()
	if err != nil {
		return fmt.Errorf("read HTTPS config to apply the new certificate: %w", err)
	}
	if https.Present == 0 {
		return fmt.Errorf("switch reports no certificate present after upload - the pair did not " +
			"install; HTTPS left as-is")
	}

	off := https
	off.Admin = 0
	if err := c.SetHTTPS(off); err != nil {
		return fmt.Errorf("disable HTTPS to force a rebuild: %w", err)
	}
	on := https
	on.Admin = 1
	if err := c.SetHTTPS(on); err != nil {
		return fmt.Errorf("re-enable HTTPS to apply the new certificate: %w", err)
	}

	// Best-effort: release the session slot.
	_ = c.Logout()
	return nil
}

// uploadCertFiles spools the certificate then the key, waiting for each to be
// accepted. It holds c.mu for the whole pair because both the write token and
// the CSRF header are session state.
func (c *Client) uploadCertFiles(certPEM, keyPEM []byte) error {
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

	if err := c.postUpload("cgi/httprootcert.cgi", certFileType, "cert.pem", certPEM); err != nil {
		return fmt.Errorf("upload certificate: %w", err)
	}
	if err := c.awaitUploadLocked(); err != nil {
		return fmt.Errorf("certificate upload: %w", err)
	}
	if err := c.postUpload("cgi/httpservercert.cgi", keyFileType, "key.pem", keyPEM); err != nil {
		return fmt.Errorf("upload private key: %w", err)
	}
	if err := c.awaitUploadLocked(); err != nil {
		return fmt.Errorf("private-key upload: %w", err)
	}
	return nil
}

// postUpload sends one multipart upload to a raw /cgi endpoint with the
// X-CSRF-XSID header. Callers hold c.mu.
func (c *Client) postUpload(path string, fileType int, filename string, content []byte) error {
	if d := time.Until(c.lastCall.Add(minInterval)); d > 0 {
		time.Sleep(d)
	}
	defer func() { c.lastCall = time.Now() }()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("fileType", strconv.Itoa(fileType)); err != nil {
		return fmt.Errorf("write fileType field: %w", err)
	}
	if err := w.WriteField("xsrf", c.xsrf); err != nil {
		return fmt.Errorf("write xsrf field: %w", err)
	}
	part, err := w.CreateFormFile("fileName", filename)
	if err != nil {
		return fmt.Errorf("create fileName part: %w", err)
	}
	if _, err := part.Write(content); err != nil {
		return fmt.Errorf("write fileName part: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close multipart body: %w", err)
	}

	// Raw /cgi path: no &dummy, no &bj4 - the UI signs neither of these uploads.
	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/"+path, &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	xsid, err := c.csrfHeader()
	if err != nil {
		return err
	}
	req.Header.Set("X-CSRF-XSID", xsid)
	// REQUIRED: the upload CGIs enforce a same-host Referer (anti-CSRF). Without
	// it the switch answers 404 even with a valid X-CSRF-XSID. Only the host is
	// checked, so the endpoint root suffices.
	req.Header.Set("Referer", c.endpoint+"/")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s returned 404 - on this switch that means the X-CSRF-XSID header was "+
			"missing, wrong, or the session expired, not that the endpoint is absent", path)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s returned HTTP %d", path, resp.StatusCode)
	}
	return nil
}

// awaitUploadLocked polls the switch's upload-status endpoint until the spooled
// file is validated and stored, or rejected. The upload POST returns before the
// switch has finished validating (the UI polls file_http_downloadStatus the same
// way). Callers hold c.mu.
func (c *Client) awaitUploadLocked() error {
	for attempt := 0; attempt < 30; attempt++ {
		var st struct {
			Status string `json:"status"`
			Msg    string `json:"msg"`
		}
		if err := c.getLocked("file_http_downloadStatus", &st); err != nil {
			return err
		}
		switch st.Status {
		case "success":
			return nil
		case "fail", "error":
			// The failure reason matters here: an EC key rejected by
			// `openssl rsa -check`, or a malformed cert rejected by
			// `openssl x509`, both surface as this status with a msg.
			return fmt.Errorf("switch rejected the file: %s", st.Msg)
		}
		// "uploading" (or anything else) - keep waiting.
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("upload never reported success or failure")
}
