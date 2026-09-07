package wax630e

import (
	"encoding/json"
	"fmt"
)

// Reboot restarts the access point.
//
//	POST /reboot  {"reboot":1}  ->  {"status":0}
//
// The AP answers BEFORE it goes down, so a nil return means the reboot was
// accepted, not that it finished. Expect roughly 60-90 seconds before it
// answers again, and note the AP serves HTTPS for about 30 seconds before its
// JSON API is actually ready - during which every call fails with an HTML body
// rather than a connection error. Wait for a real answer, not for the port.
//
// THIS DROPS EVERY WIRELESS CLIENT. Nothing wired is affected: the AP carries
// no cluster traffic and is not on the storage path.
//
// A reboot also clears the AP's session table, which is the one reason to
// reach for it deliberately. The device caps concurrent logins and frees them
// only on a long idle timeout, so a tool that exits without logging out - any
// tool that calls log.Fatal on error, since that skips deferred calls - leaks
// a slot each time it fails. Enough of those and every login is refused with
// status 401 until they expire.
//
// THE CATCH: this call needs a session itself, so it cannot dig you out of
// that hole. If logins are already being refused, the way back is to cut power
// to the AP - on this network it is PoE-powered from port 5 of the MS510TXUP,
// so the ms510txup client's SetPoEPort does it without touching the AP at all.
func (c *Client) Reboot() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" {
		if err := c.login(); err != nil {
			return err
		}
	}
	_, raw, err := c.post(map[string]any{"reboot": 1},
		map[string]string{"__path": "/reboot", "security": c.token})
	if err != nil {
		return err
	}
	// The session dies with the reboot; forget it so the next call logs in
	// rather than reusing a token the AP has already thrown away.
	c.token = ""

	var out struct {
		Status json.Number `json:"status"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("decode reboot reply: %w (body %.120s)", err, raw)
	}
	if out.Status.String() != "0" {
		return fmt.Errorf("the access point refused to reboot (status %s)", out.Status)
	}
	return nil
}
