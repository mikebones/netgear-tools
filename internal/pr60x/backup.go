package pr60x

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
)

// Backup generates and downloads an encrypted configuration backup.
//
// The web UI does this in two steps, and so does this method:
//
//  1. RPC backupSettings{password} over /socketCommunication - the AP tars
//     /etc/config/ and /etc/.cert_store, gzip+AES-256-CBC-encrypts the archive
//     with a key derived (libgcrypt KDF) from the supplied password, and parks
//     it at /var/run/backup_settings.enc.
//  2. GET /cgiBroker?backup_settings=1 (Security header + session cookie) -
//     streams that .enc back, with the real filename in Content-Disposition.
//
// The password is the ARCHIVE encryption password, chosen by the caller - not
// the admin login. The returned bytes are that encrypted archive; decrypt with
// the same password. It contains every secret in the config, so treat it like
// one (Vault, not a repo).
func (c *Client) Backup(password string) (filename string, data []byte, err error) {
	if password == "" {
		return "", nil, fmt.Errorf("a backup password is required (it encrypts the archive)")
	}
	// Step 1: ask the AP to generate the archive. Call() logs in if needed and
	// populates c.token, which the download in step 2 also needs.
	if err := c.Call("backupSettings", map[string]any{"password": password}, nil); err != nil {
		return "", nil, fmt.Errorf("backupSettings (generate): %w", err)
	}

	// Step 2: download it.
	req, err := http.NewRequest(http.MethodGet, c.endpoint+"/cgiBroker?backup_settings=1", nil)
	if err != nil {
		return "", nil, err
	}
	if c.token != "" {
		req.Header.Set("Security", c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("download backup: %w", err)
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("download backup: HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	filename = "pr60x-backup.enc"
	if _, params, e := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); e == nil {
		if n := params["filename"]; n != "" {
			filename = n
		}
	}
	return filename, data, nil
}

// Restore uploads a (previously downloaded, optionally modified) encrypted
// backup and applies it, in the two steps the web UI uses:
//
//  1. POST /cgiBroker?restore_settings=1 multipart with fields "file" (the .enc
//     bytes) and "filename" - the CGI parks it at /tmp/cgiBroker.restore_settings.
//  2. RPC restoreSettings{password} - gf-configd (root) decrypts that file with
//     the password, `tar zxf` it to /var/run/restore, `cp -r
//     /var/run/restore/etc/config/ /etc/` (ONLY /etc/config is promoted),
//     reloads UCI, and REBOOTS. It returns {restoreStatus:"normal"} on success.
//
// DANGER: this reboots the device and drops all traffic. Only restore an archive
// built from a real Backup() of THIS device; the password must match the one the
// archive was encrypted with. NOTE the copy scope: files placed OUTSIDE
// etc/config in the archive are extracted but NOT copied to the live /etc.
func (c *Client) Restore(data []byte, password string) error {
	if len(data) == 0 {
		return fmt.Errorf("empty backup data")
	}
	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
	}
	// Step 1: upload the encrypted archive.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile("file", "restore.enc")
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	_ = w.WriteField("filename", "restore.enc")
	if err := w.Close(); err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/cgiBroker?restore_settings=1", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if c.token != "" {
		req.Header.Set("Security", c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("restore upload: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("restore upload: HTTP %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	// Step 2: apply. gf-configd decrypts with the password, restores, reboots.
	var out struct {
		RestoreStatus string `json:"restoreStatus"`
	}
	if err := c.Call("restoreSettings", map[string]any{"password": password}, &out); err != nil {
		return fmt.Errorf("restoreSettings (apply): %w", err)
	}
	if out.RestoreStatus != "" && out.RestoreStatus != "normal" {
		return fmt.Errorf("restore rejected: restoreStatus=%q", out.RestoreStatus)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
