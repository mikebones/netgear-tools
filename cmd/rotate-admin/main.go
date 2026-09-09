// Command rotate-admin rotates a NETGEAR appliance's admin password and keeps
// Vault and the device from ever silently diverging — without EVER losing the
// new password.
//
// It replaces an ad-hoc shell script that lost a PR60X password. That script
// had three bugs, and this command makes each one structurally impossible:
//
//   - It ran the rotation TWICE, so the second run failed against the
//     already-changed password. Here the rotation is one straight line called
//     exactly once (see rotate.go): no loop, no retry of the device change.
//   - Its Vault write was gated on an exit code a later failing step clobbered,
//     so the write was skipped. Here the new password is written to Vault
//     FIRST and unconditionally, before the device is touched at all.
//   - A grep -v hid the success line, so the operator misread the result. Here
//     the outcome is a typed value mapped straight to an exit code, and there
//     is no output filtering anywhere.
//
// # Safety guarantee
//
// After the Vault write succeeds, the new password exists durably. From that
// point a crash, panic, or kill cannot lose it. Exit codes reflect the ACTUAL
// device state:
//
//	0  success: Vault=new, device=new, verified.
//	1  precondition failure: nothing changed anywhere (bad flags/env, secret
//	   missing, no current password in Vault, generation or the first Vault
//	   write failed). Device still on old, Vault still holds old.
//	2  device change failed cleanly; Vault rolled back to old. The two agree.
//	3  change reported success but verify failed; Vault KEPT new — confirm the
//	   device manually.
//	4  device change failed AND the rollback failed: Vault=new, device=old.
//	   Reconcile manually.
//
// The password itself is NEVER printed.
//
// # Requirements
//
// The CURRENT admin password must already be in Vault at secret/netgear/<device>
// (field "password"): the device's change RPC needs the old password as input.
// This is why the command cannot recover a password that was already lost — but
// it is correct for every future rotation and for the other devices.
//
// # Usage
//
//	export VAULT_ADDR=https://vault.example.com:8200
//	export VAULT_TOKEN=...            # a token allowed to read+write the secret
//	rotate-admin -device pr60x -endpoint https://198.51.100.1
//
// This is a one-shot CLI: it runs once and exits. It starts no background work
// and leaves no lingering process.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run parses flags, wires Vault + the device, performs ONE rotation, and
// returns the exit code. It is a function (not inline in main) so its exit code
// is testable and so main stays a single os.Exit.
func run(args []string) int {
	fs := flag.NewFlagSet("rotate-admin", flag.ContinueOnError)
	var (
		device    = fs.String("device", "pr60x", "Device kind to rotate (currently: pr60x).")
		endpoint  = fs.String("endpoint", envOr("NETGEAR_ENDPOINT", "https://192.0.2.1"), "Device base URL. Use env NETGEAR_ENDPOINT; do NOT commit a real LAN IP.")
		username  = fs.String("username", envOr("NETGEAR_USERNAME", "admin"), "Device admin username.")
		insecure  = fs.Bool("insecure", true, "Skip TLS verification (appliances serve self-signed certs on private IPs).")
		vaultPath = fs.String("vault-path", "", "Secret path under the mount (default: netgear/<device>).")
		mount     = fs.String("mount", envOr("VAULT_KV_MOUNT", "secret"), "Vault KV mount.")
		field     = fs.String("field", "password", "Field within the secret holding the password.")
		kvV2      = fs.Bool("kv2", true, "Secret is stored in a KV v2 mount (false = KV v1).")
		length    = fs.Int("length", 20, "Length of the generated password (minimum 8).")
	)
	if err := fs.Parse(args); err != nil {
		return int(OutcomePrecondition)
	}

	factory, ok := deviceFactories[*device]
	if !ok {
		fmt.Fprintf(os.Stderr, "unknown device %q; known: %s\n", *device, knownDevices())
		return int(OutcomePrecondition)
	}

	secretPath := *vaultPath
	if secretPath == "" {
		secretPath = "netgear/" + *device
	}

	store, err := newVaultKV(os.Getenv("VAULT_ADDR"), os.Getenv("VAULT_TOKEN"), *mount, *kvV2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vault config: %v\n", err)
		return int(OutcomePrecondition)
	}

	dev, err := factory(*endpoint, *username, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "device config: %v\n", err)
		return int(OutcomePrecondition)
	}

	logf := func(s string) { fmt.Fprintln(os.Stderr, s) }
	gen := func() (string, error) { return generatePassword(*length) }

	fmt.Fprintf(os.Stderr, "rotating %s admin password (Vault %s, endpoint %s)\n", *device, secretPath, *endpoint)

	outcome, err := rotate(store, dev, secretPath, *field, gen, logf)

	// Report the result plainly. No filtering, and never the password.
	switch outcome {
	case OutcomeSuccess:
		fmt.Fprintln(os.Stderr, "SUCCESS: Vault and device both on the new password (verified).")
	case OutcomePrecondition:
		fmt.Fprintf(os.Stderr, "PRECONDITION FAILURE (nothing changed): %v\n", err)
	case OutcomeRolledBack:
		fmt.Fprintf(os.Stderr, "FAILED, ROLLED BACK (device still on old password, Vault restored): %v\n", err)
	case OutcomeChangedVerifyFlaky:
		fmt.Fprintf(os.Stderr, "CHANGED BUT VERIFY FLAKY (Vault KEEPS new password, confirm device manually): %v\n", err)
	case OutcomeDiverged:
		fmt.Fprintf(os.Stderr, "DIVERGED (Vault=new, device=old, reconcile manually): %v\n", err)
	default:
		fmt.Fprintf(os.Stderr, "unexpected outcome %d: %v\n", outcome, err)
	}

	return int(outcome)
}

func knownDevices() string {
	names := make([]string, 0, len(deviceFactories))
	for k := range deviceFactories {
		names = append(names, k)
	}
	// Small set; a stable-enough join is fine.
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
