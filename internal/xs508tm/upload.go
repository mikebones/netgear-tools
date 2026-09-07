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

// CertFileType selects which half of the key pair an upload carries.
//
// UNUSED until the upload field names are known - kept because these are the
// options the device's own File Type selector offers, and the distinction
// they encode is the one people get wrong: a trusted ROOT is a CA the switch
// should trust, not the switch's own identity. Uploading a Let's Encrypt
// chain as a trusted root does not make the switch serve it.
type CertFileType int

const (
	// CertFileServerCert is the signed server certificate (PEM).
	CertFileServerCert CertFileType = 1
	// CertFileServerKey is the matching private key (PEM).
	CertFileServerKey CertFileType = 2
	// CertFileTrustedRoot is a CA certificate to trust, NOT the switch's own
	// identity - uploading a Let's Encrypt chain here does not make the switch
	// serve it.
	CertFileTrustedRoot CertFileType = 3
)

// UploadCertificate is NOT IMPLEMENTED, and returns an explanation instead of
// a wrong guess.
//
// WHAT IS ESTABLISHED. The route is POST /api/v1/https_cert_upld. It exists:
// GET returns 404, POST is accepted. And it PARSES ITS BODY AS JSON - sending
// multipart/form-data gets
//
//	400: Failed to parse json data.
//
// which is the useful error. Every JSON body, by contrast, parses fine and
// returns the content-free
//
//	{"resp":{"respCode":-99,"status":"failure"}}
//
// so -99 means "parsed, but the fields are wrong", not "wrong encoding".
//
// WHAT IS NOT. The field names. Ten shapes have been tried and all return
// -99: {fileType,fileName,fileContent}, {certificate,privatekey},
// {type,content}, {cert,key}, {data}, {content,type}, base64 variants of
// each, both bare and wrapped in an https_cert_upld envelope.
//
// HOW TO FINISH IT. Capture the real request. The upload form lives in a
// lazy-loaded chunk rather than the main bundle, so grepping does not find
// it; open the page with an XHR recorder installed and upload any file. The
// field names fall straight out. That is how every other write payload on
// these devices was learned - see netgear-tools/docs/ms510txup-web-ui.md.
//
// Guessing further is not worth it: this is the one call that can take a
// switch's management interface off the network if it half-applies, and the
// device gives no signal about which field was wrong.
func (c *Client) UploadCertificate(certPEM, keyPEM []byte) error {
	return fmt.Errorf("https_cert_upld field names are not known yet: the route parses JSON " +
		"(multipart returns 400 \"Failed to parse json data\") but every field shape tried " +
		"returns respCode -99. Capture the real request from the switch's own upload form with " +
		"an XHR recorder, then implement it here")
}
