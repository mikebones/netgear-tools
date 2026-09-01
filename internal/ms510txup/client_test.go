package ms510txup

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
)

// TestObfuscatePasswordRoundTrip checks the port of the switch's encode()
// against the algorithm's own inverse.
//
// Worth testing because a wrong obfuscation is indistinguishable from a wrong
// password at the device, and the switch locks the account after five
// failures - so an error here costs a lockout, not a message.
func TestObfuscatePasswordRoundTrip(t *testing.T) {
	// Synthetic vectors only - never a real device credential. These run in a
	// public repository.
	//
	// Deliberately all short. The scheme only holds for passwords under about
	// 32 characters: the output is 320-len(pw) long, so beyond that the length
	// digits at indices 123 and 289 fall off the end and the encoding is not
	// representable. Real switch passwords are well inside that.
	for _, pw := range []string{"a", "short1", "Xy@7z%3qfR^8k*", "0123456789abcdef0123"} {
		got := obfuscatePassword(pw)
		if want := 320 - len(pw); len(got) != want {
			t.Errorf("%q: length = %d, want %d", pw, len(got), want)
			continue
		}

		// The password's characters sit at every 7th position, in reverse.
		var chars []byte
		for i := 1; i <= len(got); i++ {
			if i%7 == 0 {
				chars = append(chars, got[i-1])
			}
		}
		if len(chars) < len(pw) {
			t.Fatalf("%q: only %d slots for %d characters", pw, len(chars), len(pw))
		}
		reversed := make([]byte, len(pw))
		for i := range reversed {
			reversed[i] = chars[len(pw)-1-i]
		}
		if string(reversed) != pw {
			t.Errorf("%q: recovered %q", pw, reversed)
		}

		// Length is encoded as a tens digit at index 123 and a ones digit at 289.
		wantTens := byte('0')
		if len(pw) >= 10 {
			wantTens = byte('0' + len(pw)/10)
		}
		if got[122] != wantTens {
			t.Errorf("%q: tens digit = %q, want %q", pw, got[122], wantTens)
		}
		if w := byte('0' + len(pw)%10); got[288] != w {
			t.Errorf("%q: ones digit = %q, want %q", pw, got[288], w)
		}
	}
}

// TestSign checks that bj4 covers exactly the query string - not the path,
// which is the easy way to get this subtly wrong.
func TestSign(t *testing.T) {
	const qs = "cmd=sys_info&dummy=123"
	sum := md5.Sum([]byte(qs))
	want := "http://host/cgi/get.cgi?" + qs + "&bj4=" + hex.EncodeToString(sum[:])
	if got := sign("http://host/cgi/get.cgi?" + qs); got != want {
		t.Errorf("sign() = %q, want %q", got, want)
	}
	if got := sign("http://host/nothing"); got != "http://host/nothing" {
		t.Errorf("a URL with no query string should be unchanged, got %q", got)
	}
}

// TestEncodeFieldsPreservesOrder guards the ordering fix: this CGI is
// order-sensitive and Go's url.Values.Encode() sorts keys, which silently
// reorders the login form and fails as a bad password.
func TestEncodeFieldsPreservesOrder(t *testing.T) {
	got := encodeFields([]Field{{"pwd", "secret"}, {"actKeyText", ""}})
	if want := "pwd=secret&actKeyText="; got != want {
		t.Errorf("encodeFields() = %q, want %q", got, want)
	}
}
