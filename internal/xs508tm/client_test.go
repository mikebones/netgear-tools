package xs508tm

import (
	"strings"
	"testing"
)

// A locked admin account is the failure this firmware returns as
// resp.status="failure" with a generic errCode (2 observed on 7.8.11.21) and
// login.locked=1. It must be reported as a lockout, not as the opaque
// "rejected by the switch (errCode 2)", so the operator looks at the account
// rather than suspecting a firmware-compatibility problem.
func TestLoginEnvelopeErrorLocked(t *testing.T) {
	reply := map[string]any{
		"resp":  map[string]any{"status": "failure", "respCode": float64(-1), "errCode": float64(2)},
		"login": map[string]any{"token": "", "expire": float64(0), "locked": float64(1)},
	}
	err := loginEnvelopeError(reply)
	if err == nil {
		t.Fatal("expected an error for a locked-account reply, got nil")
	}
	if !strings.Contains(err.Error(), "locked") {
		t.Errorf("locked reply should name the lockout; got: %v", err)
	}
}

// A plain rejection (wrong creds / session table full) is errCode 481 with no
// lock flag, and must keep its own message rather than being reported as a lock.
func TestLoginEnvelopeErrorRejected(t *testing.T) {
	reply := map[string]any{
		"resp":  map[string]any{"status": "failure", "errCode": float64(errCodeLoginRejected)},
		"login": map[string]any{"locked": float64(0)},
	}
	err := loginEnvelopeError(reply)
	if err == nil {
		t.Fatal("expected an error for errCode 481, got nil")
	}
	if strings.Contains(err.Error(), "locked") {
		t.Errorf("errCode 481 without a lock flag should not be reported as a lockout; got: %v", err)
	}
	if !strings.Contains(err.Error(), "481") {
		t.Errorf("expected the errCode in the message; got: %v", err)
	}
}

// A successful login envelope must produce no error.
func TestLoginEnvelopeErrorSuccess(t *testing.T) {
	if err := loginEnvelopeError(map[string]any{
		"resp":  map[string]any{"status": "success"},
		"login": map[string]any{"token": "abc"},
	}); err != nil {
		t.Errorf("success envelope should not error; got: %v", err)
	}
	// No resp envelope at all is also not an error at this layer.
	if err := loginEnvelopeError(map[string]any{"login": map[string]any{"token": "abc"}}); err != nil {
		t.Errorf("missing resp envelope should not error; got: %v", err)
	}
}

func TestLoginIsLocked(t *testing.T) {
	cases := []struct {
		name  string
		reply map[string]any
		want  bool
	}{
		{"locked float", map[string]any{"login": map[string]any{"locked": float64(1)}}, true},
		{"locked bool", map[string]any{"login": map[string]any{"locked": true}}, true},
		{"not locked", map[string]any{"login": map[string]any{"locked": float64(0)}}, false},
		{"no login key", map[string]any{"resp": map[string]any{}}, false},
		{"no locked key", map[string]any{"login": map[string]any{"token": ""}}, false},
	}
	for _, tc := range cases {
		if got := loginIsLocked(tc.reply); got != tc.want {
			t.Errorf("%s: loginIsLocked=%v want %v", tc.name, got, tc.want)
		}
	}
}
