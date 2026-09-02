package provider

import "sync"

// Sessions opened against these devices outlive the process that opened them.
// The switches free a session on logout or on an idle timeout - never because
// the client went away. Terraform runs a provider as a short-lived process, so
// without an explicit hand-back every run leaks one, and these session tables
// are small enough that a day of ordinary use ends in refused logins. That is
// not hypothetical: it is how both the access point and the XS508TM locked us
// out mid-project.
//
// Devices whose login is one cheap round trip release the session inside each
// call instead. This registry covers the rest, where re-authenticating per
// call would mean paying for a multi-step handshake every time.
//
// It is a best-effort net, not a guarantee: it runs when the plugin server
// shuts down cleanly, and a killed process still leaks. It is the cheap half
// of the fix, and the per-call release is the half that actually holds.
var (
	cleanupMu sync.Mutex
	cleanups  []func()
)

func registerCleanup(fn func()) {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	cleanups = append(cleanups, fn)
}

// Cleanup hands back every session this process is holding. main calls it once
// the plugin server has stopped.
func Cleanup() {
	cleanupMu.Lock()
	defer cleanupMu.Unlock()
	for _, fn := range cleanups {
		fn()
	}
	cleanups = nil
}
