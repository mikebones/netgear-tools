package main

import (
	"fmt"

	"netgear-tools/internal/pr60x"
)

// deviceFactory builds a Device for one kind of device. Adding xs508tm / wax /
// ms510 is a matter of writing one of these and registering it in
// deviceFactories below; rotate() itself never changes.
type deviceFactory func(endpoint, username string, insecure bool) (Device, error)

// deviceFactories is the registry keyed by the -device flag. Only pr60x is
// wired today; the others have a clear slot.
var deviceFactories = map[string]deviceFactory{
	"pr60x": newPR60XDevice,
	// "xs508tm": newXS508TMDevice,  // internal/xs508tm — REST admin change
	// "wax630e": newWAX630EDevice,  // internal/wax630e
	// "ms510txup": newMS510Device,  // internal/ms510txup
}

// pr60xDevice adapts internal/pr60x to the Device contract.
//
// Every operation builds its OWN short-lived client, on purpose. The PR60X
// invalidates the session on a password change and re-logs-in with whatever
// password its Client was constructed with (see pr60x.SetAdminPassword's
// doc). Building a fresh client per call keeps the old and new credentials from
// ever being mixed inside one client's retry path.
type pr60xDevice struct {
	endpoint string
	username string
	insecure bool
}

func newPR60XDevice(endpoint, username string, insecure bool) (Device, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("pr60x: endpoint is required (set -endpoint or NETGEAR_ENDPOINT)")
	}
	if username == "" {
		username = "admin"
	}
	return &pr60xDevice{endpoint: endpoint, username: username, insecure: insecure}, nil
}

// SetPassword changes the admin credential on the router, once.
func (d *pr60xDevice) SetPassword(oldPassword, newPassword string) error {
	c, err := pr60x.NewClient(d.endpoint, d.username, oldPassword, d.insecure)
	if err != nil {
		return fmt.Errorf("pr60x: build client: %w", err)
	}
	defer c.Logout()
	return c.SetAdminPassword(oldPassword, newPassword)
}

// Verify logs in fresh with the candidate password and makes one authenticated
// call. A nil return means the password genuinely works.
func (d *pr60xDevice) Verify(password string) error {
	c, err := pr60x.NewClient(d.endpoint, d.username, password, d.insecure)
	if err != nil {
		return fmt.Errorf("pr60x: build verify client: %w", err)
	}
	defer c.Logout()
	if _, err := c.GetDeviceInfo(); err != nil {
		return fmt.Errorf("pr60x: verify login/call failed: %w", err)
	}
	return nil
}
