package main

// rotate.go holds the device- and Vault-agnostic core of the rotator. It talks
// only to the SecretStore and Device interfaces so it can be unit-tested with
// mocks, and so xs508tm / wax / ms510 slot in by writing a Device adapter
// rather than touching this logic.
//
// This file is the structural fix for the three bugs in the ad-hoc script that
// lost a PR60X password:
//
//   - It ran the rotation TWICE (the 2nd run failed against the already-changed
//     password). Here rotate() is a single straight line with no loop and no
//     retry of the device change, and main calls it exactly once.
//   - The Vault write was gated on an exit code a later failing step clobbered,
//     so the write was skipped. Here the Vault write happens FIRST and
//     unconditionally, before the device is touched at all.
//   - A grep -v hid the success line so the operator misread the result. Here
//     the outcome is a typed value that maps directly to an exit code; there is
//     no text filtering anywhere.

import "fmt"

// Device is the minimal contract the rotator needs from a target. internal/
// pr60x satisfies it via the adapter in device_pr60x.go; other devices are
// added the same way.
type Device interface {
	// SetPassword changes the admin credential from oldPassword to newPassword
	// on the device. It must be called at most once per rotation.
	SetPassword(oldPassword, newPassword string) error

	// Verify performs a FRESH, fully authenticated login/call using password
	// and returns nil only if that actually succeeded. It must not reuse any
	// session created by SetPassword.
	Verify(password string) error
}

// SecretStore is the minimal contract the rotator needs from Vault. The
// concrete implementation is vaultKV in vault.go.
type SecretStore interface {
	// Read returns every field of the secret at path. A missing secret is an
	// error, not an empty map.
	Read(path string) (map[string]string, error)

	// Write stores data as the complete set of fields at path. The rotator
	// always passes the full field set it read back (with one field changed),
	// so nothing is dropped — this is the "merge, preserve other fields"
	// behaviour.
	Write(path string, data map[string]string) error
}

// Outcome is the machine-readable result of a rotation. Its integer value IS
// the process exit code, so callers never have to translate. Nothing branches
// on log text.
type Outcome int

const (
	// OutcomeSuccess: Vault holds the new password, the device is on the new
	// password, and a fresh login with it succeeded.
	OutcomeSuccess Outcome = 0

	// OutcomePrecondition: a check before the device was ever touched failed
	// (no VAULT env, secret missing, no current password in Vault, generation
	// or the first Vault write failed). Nothing changed anywhere; the device is
	// still on the old password and Vault still holds it.
	OutcomePrecondition Outcome = 1

	// OutcomeRolledBack: the device change failed cleanly (the device is
	// provably still on the OLD password) and Vault was rolled back to the old
	// password. The two agree again; safe to re-run.
	OutcomeRolledBack Outcome = 2

	// OutcomeChangedVerifyFlaky: the change RPC reported success but the
	// confirming fresh login did not land. The device is very likely already on
	// the NEW password, so Vault KEEPS the new password. A human should confirm
	// the device manually.
	OutcomeChangedVerifyFlaky Outcome = 3

	// OutcomeDiverged: the device change failed AND the Vault rollback also
	// failed. Vault now holds the NEW password but the device is still on the
	// OLD one. This is the one state that needs a human to reconcile; it is
	// reported loudly rather than hidden behind the original error.
	OutcomeDiverged Outcome = 4
)

// rotate performs EXACTLY ONE admin-password rotation.
//
// Ordering, which is the entire point:
//
//  1. Read the current secret (need the old password + the other fields).
//  2. Generate the new password.
//  3. WRITE THE NEW PASSWORD TO VAULT — first, unconditionally. After this
//     line returns nil the new password exists durably, so any crash, panic,
//     or kill below cannot lose it.
//  4. Change the password on the device, once, with no retry.
//  5. Verify with a fresh login using the new password.
//
// gen returns a fresh strong password; logf (may be nil) receives progress
// lines that NEVER contain a password. The returned error is descriptive; the
// returned Outcome is authoritative for the exit code.
func rotate(store SecretStore, dev Device, path, field string, gen func() (string, error), logf func(string)) (Outcome, error) {
	log := func(s string) {
		if logf != nil {
			logf(s)
		}
	}

	// 1. Read the current secret. We need the OLD password for the change RPC
	//    and every other field so the write preserves them.
	secret, err := store.Read(path)
	if err != nil {
		return OutcomePrecondition, fmt.Errorf("read current secret %q from Vault: %w", path, err)
	}
	oldPassword := secret[field]
	if oldPassword == "" {
		return OutcomePrecondition, fmt.Errorf(
			"secret %q has no non-empty %q field: the CURRENT password must already be in Vault for this to rotate it — see the README (this is why it cannot fix a password that was already lost)",
			path, field)
	}

	// 2. Generate the new password.
	newPassword, err := gen()
	if err != nil {
		return OutcomePrecondition, fmt.Errorf("generate new password: %w", err)
	}

	// 3. WRITE THE NEW PASSWORD TO VAULT FIRST — before any device call, with
	//    no condition guarding it. Every other field is carried through
	//    unchanged (merge/preserve).
	newSecret := cloneWith(secret, field, newPassword)
	if err := store.Write(path, newSecret); err != nil {
		// The device was never touched, so it is still on the old password and
		// Vault still holds it. Nothing lost; a plain precondition failure.
		return OutcomePrecondition, fmt.Errorf("write new password to Vault (device NOT touched, nothing changed): %w", err)
	}
	log("new password written to Vault; changing it on the device now")

	// 4. Change the password on the device. EXACTLY ONCE. No loop, no retry.
	if err := dev.SetPassword(oldPassword, newPassword); err != nil {
		// Clean failure: the device rejected the change and is provably still on
		// the OLD password. Roll Vault back so the two agree again.
		log("device change failed; rolling Vault back to the old password")
		if rbErr := store.Write(path, secret); rbErr != nil {
			// Rollback failed too: Vault=new, device=old. Real divergence.
			return OutcomeDiverged, fmt.Errorf(
				"device change failed (%v) AND Vault rollback failed (%v): Vault now holds the NEW password but the device is still on the OLD one — reconcile manually",
				err, rbErr)
		}
		return OutcomeRolledBack, fmt.Errorf("device change failed; Vault rolled back to the old password: %w", err)
	}

	// 5. Verify with a FRESH login using the new password.
	if err := dev.Verify(newPassword); err != nil {
		// The change RPC said it worked but the confirming login did not land.
		// The device is very likely already on the new password, so rolling
		// Vault back here would be how we LOSE access. Keep Vault=new and flag
		// it for a human.
		return OutcomeChangedVerifyFlaky, fmt.Errorf(
			"device reported the change succeeded but re-login with the new password failed: Vault KEEPS the new password — confirm the device manually: %w",
			err)
	}

	log("rotation complete: Vault and device are both on the new password, verified")
	return OutcomeSuccess, nil
}

// cloneWith returns a copy of m with key set to val, leaving m untouched. The
// copy is what lets rotate() hold the original (old) secret for rollback while
// writing the modified (new) one.
func cloneWith(m map[string]string, key, val string) map[string]string {
	out := make(map[string]string, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	out[key] = val
	return out
}
