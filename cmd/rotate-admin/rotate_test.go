package main

import (
	"errors"
	"strings"
	"testing"
)

// --- test doubles ----------------------------------------------------------

// fakeStore is an in-memory SecretStore that records every write in order and
// can be told to fail a specific write (by call index) so rollback paths are
// exercisable.
type fakeStore struct {
	cur       map[string]string
	writeLog  []map[string]string // a clone of the data passed to each Write, in order
	readErr   error
	writeErrs map[int]error // write-call-index -> error to return
	writeN    int
}

func newFakeStore(cur map[string]string) *fakeStore {
	return &fakeStore{cur: cloneMap(cur), writeErrs: map[int]error{}}
}

func (f *fakeStore) Read(path string) (map[string]string, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	if f.cur == nil {
		return map[string]string{}, nil
	}
	return cloneMap(f.cur), nil
}

func (f *fakeStore) Write(path string, data map[string]string) error {
	i := f.writeN
	f.writeN++
	f.writeLog = append(f.writeLog, cloneMap(data))
	if err := f.writeErrs[i]; err != nil {
		return err // NOTE: cur is deliberately NOT updated on a failed write.
	}
	f.cur = cloneMap(data)
	return nil
}

// fakeDevice is a Device double. onSet runs at the top of SetPassword, before
// any error is returned, which lets a test observe Vault's state at the exact
// moment the device is about to change — proving write-before-change ordering.
type fakeDevice struct {
	setErr      error
	verifyErr   error
	setCalls    int
	verifyCalls int
	gotOld      string
	gotNew      string
	onSet       func()
}

func (d *fakeDevice) SetPassword(oldPassword, newPassword string) error {
	d.setCalls++
	d.gotOld, d.gotNew = oldPassword, newPassword
	if d.onSet != nil {
		d.onSet()
	}
	return d.setErr
}

func (d *fakeDevice) Verify(password string) error {
	d.verifyCalls++
	return d.verifyErr
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

const newPW = "NEWpassw0rd-Xy=1"

func fixedGen() (string, error) { return newPW, nil }

// --- tests -----------------------------------------------------------------

// The core ordering guarantee: the new password is in Vault BEFORE the device
// change RPC runs, and the other fields are preserved.
func TestRotate_WritesVaultBeforeDeviceChange(t *testing.T) {
	store := newFakeStore(map[string]string{"password": "OLDpw", "note": "keep-me"})

	var pwAtDeviceChange string
	dev := &fakeDevice{onSet: func() {
		pwAtDeviceChange = store.cur["password"]
	}}

	outcome, err := rotate(store, dev, "netgear/pr60x", "password", fixedGen, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != OutcomeSuccess {
		t.Fatalf("outcome = %d, want OutcomeSuccess", outcome)
	}
	if pwAtDeviceChange != newPW {
		t.Fatalf("Vault held %q when the device change started, want the new password %q (write-before-change violated)", pwAtDeviceChange, newPW)
	}
	if dev.gotOld != "OLDpw" || dev.gotNew != newPW {
		t.Fatalf("SetPassword(%q,%q); want (OLDpw,%q)", dev.gotOld, dev.gotNew, newPW)
	}
	if store.cur["password"] != newPW {
		t.Fatalf("final Vault password = %q, want %q", store.cur["password"], newPW)
	}
	if store.cur["note"] != "keep-me" {
		t.Fatalf("other field not preserved: note = %q", store.cur["note"])
	}
	if dev.setCalls != 1 {
		t.Fatalf("SetPassword called %d times, want exactly 1 (run-once)", dev.setCalls)
	}
	if dev.verifyCalls != 1 {
		t.Fatalf("Verify called %d times, want 1", dev.verifyCalls)
	}
}

// Clean device failure => Vault rolled back to the old password, verify never
// attempted.
func TestRotate_RollbackOnCleanFailure(t *testing.T) {
	store := newFakeStore(map[string]string{"password": "OLDpw", "note": "keep-me"})
	dev := &fakeDevice{setErr: errors.New("bad old password")}

	outcome, err := rotate(store, dev, "netgear/pr60x", "password", fixedGen, nil)
	if outcome != OutcomeRolledBack {
		t.Fatalf("outcome = %d, want OutcomeRolledBack", outcome)
	}
	if err == nil {
		t.Fatal("expected an error describing the rollback")
	}
	if store.cur["password"] != "OLDpw" {
		t.Fatalf("Vault password = %q after rollback, want OLDpw", store.cur["password"])
	}
	if store.cur["note"] != "keep-me" {
		t.Fatalf("other field lost during rollback: note = %q", store.cur["note"])
	}
	// Two writes: new, then the rollback to old.
	if len(store.writeLog) != 2 {
		t.Fatalf("writes = %d, want 2 (new then rollback)", len(store.writeLog))
	}
	if store.writeLog[0]["password"] != newPW || store.writeLog[1]["password"] != "OLDpw" {
		t.Fatalf("write order wrong: %q then %q", store.writeLog[0]["password"], store.writeLog[1]["password"])
	}
	if dev.verifyCalls != 0 {
		t.Fatalf("Verify called %d times on a clean failure, want 0", dev.verifyCalls)
	}
}

// Change RPC succeeds but verify fails => Vault KEEPS the new password.
func TestRotate_KeepOnFlakyVerify(t *testing.T) {
	store := newFakeStore(map[string]string{"password": "OLDpw"})
	dev := &fakeDevice{verifyErr: errors.New("login timed out")}

	outcome, err := rotate(store, dev, "netgear/pr60x", "password", fixedGen, nil)
	if outcome != OutcomeChangedVerifyFlaky {
		t.Fatalf("outcome = %d, want OutcomeChangedVerifyFlaky", outcome)
	}
	if err == nil || !strings.Contains(err.Error(), "KEEPS") {
		t.Fatalf("error should say the new password is kept; got %v", err)
	}
	if store.cur["password"] != newPW {
		t.Fatalf("Vault password = %q, want the NEW password kept (%q)", store.cur["password"], newPW)
	}
	if len(store.writeLog) != 1 {
		t.Fatalf("writes = %d, want exactly 1 (no rollback on flaky verify)", len(store.writeLog))
	}
}

// Device change fails AND the rollback write fails => diverged, reported as
// such, and Vault still holds the new password (the rollback did not commit).
func TestRotate_DivergedWhenRollbackFails(t *testing.T) {
	store := newFakeStore(map[string]string{"password": "OLDpw"})
	store.writeErrs[1] = errors.New("vault write denied") // fail the rollback (2nd write)
	dev := &fakeDevice{setErr: errors.New("device unreachable")}

	outcome, err := rotate(store, dev, "netgear/pr60x", "password", fixedGen, nil)
	if outcome != OutcomeDiverged {
		t.Fatalf("outcome = %d, want OutcomeDiverged", outcome)
	}
	if err == nil || !strings.Contains(err.Error(), "reconcile manually") {
		t.Fatalf("error should flag manual reconciliation; got %v", err)
	}
	if store.cur["password"] != newPW {
		t.Fatalf("Vault password = %q, want the NEW password (rollback did not commit)", store.cur["password"])
	}
}

// The safety invariant, tested directly: if the device call panics (an
// early/abnormal exit after the Vault write), the new password is already in
// Vault and is not lost.
func TestRotate_PanicAfterVaultWriteDoesNotLosePassword(t *testing.T) {
	store := newFakeStore(map[string]string{"password": "OLDpw"})
	dev := &fakeDevice{onSet: func() { panic("device blew up mid-change") }}

	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected the device panic to propagate")
			}
		}()
		_, _ = rotate(store, dev, "netgear/pr60x", "password", fixedGen, nil)
	}()

	if store.cur["password"] != newPW {
		t.Fatalf("after a panic the Vault password = %q, want the NEW password %q — it must NOT be lost", store.cur["password"], newPW)
	}
}

// No current password in Vault => precondition failure, device never touched.
func TestRotate_PreconditionNoCurrentPassword(t *testing.T) {
	store := newFakeStore(map[string]string{"note": "no password field here"})
	dev := &fakeDevice{}

	outcome, err := rotate(store, dev, "netgear/pr60x", "password", fixedGen, nil)
	if outcome != OutcomePrecondition {
		t.Fatalf("outcome = %d, want OutcomePrecondition", outcome)
	}
	if err == nil {
		t.Fatal("expected an error explaining the missing current password")
	}
	if dev.setCalls != 0 {
		t.Fatalf("device touched %d times on a precondition failure, want 0", dev.setCalls)
	}
	if len(store.writeLog) != 0 {
		t.Fatalf("Vault written %d times before the precondition check, want 0", len(store.writeLog))
	}
}

// The first Vault write failing must leave the device untouched (nothing lost).
func TestRotate_FirstVaultWriteFailsLeavesDeviceUntouched(t *testing.T) {
	store := newFakeStore(map[string]string{"password": "OLDpw"})
	store.writeErrs[0] = errors.New("vault sealed")
	dev := &fakeDevice{}

	outcome, _ := rotate(store, dev, "netgear/pr60x", "password", fixedGen, nil)
	if outcome != OutcomePrecondition {
		t.Fatalf("outcome = %d, want OutcomePrecondition", outcome)
	}
	if dev.setCalls != 0 {
		t.Fatalf("device changed despite the Vault write failing; setCalls = %d", dev.setCalls)
	}
	if store.cur["password"] != "OLDpw" {
		t.Fatalf("Vault password = %q, want it unchanged at OLDpw", store.cur["password"])
	}
}
