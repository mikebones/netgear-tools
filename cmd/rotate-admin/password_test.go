package main

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	// Characters that must never appear: ':' and shell/JSON metacharacters.
	forbidden := ":\"'\\`$!*?;&|<>(){}[]#~% ^"

	for i := 0; i < 500; i++ {
		pw, err := generatePassword(24)
		if err != nil {
			t.Fatalf("generatePassword: %v", err)
		}
		if len(pw) != 24 {
			t.Fatalf("length = %d, want 24", len(pw))
		}
		if !strings.ContainsAny(pw, pwLowers) {
			t.Fatalf("no lower-case letter in %q", pw)
		}
		if !strings.ContainsAny(pw, pwUppers) {
			t.Fatalf("no upper-case letter in %q", pw)
		}
		if !strings.ContainsAny(pw, pwDigits) {
			t.Fatalf("no digit in %q", pw)
		}
		if !strings.ContainsAny(pw, pwSymbols) {
			t.Fatalf("no safe symbol in %q", pw)
		}
		if strings.ContainsAny(pw, forbidden) {
			t.Fatalf("password %q contains a forbidden character", pw)
		}
	}
}

func TestGeneratePasswordShortLengthBumped(t *testing.T) {
	pw, err := generatePassword(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) < 8 {
		t.Fatalf("short length was not bumped: got %d", len(pw))
	}
}

func TestGeneratePasswordUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		pw, err := generatePassword(20)
		if err != nil {
			t.Fatal(err)
		}
		if seen[pw] {
			t.Fatalf("duplicate password generated: %q", pw)
		}
		seen[pw] = true
	}
}
