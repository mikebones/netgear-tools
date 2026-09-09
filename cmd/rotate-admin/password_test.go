package main

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	// The generated password must draw ONLY from the allowed pool. This is the
	// real invariant: the PR60X backend rejects any character outside its
	// special-char whitelist with DAI error 18, so a stray symbol would fail a
	// live rotation. pwSymbols is already inside that whitelist (see password.go).
	allowed := pwLowers + pwUppers + pwDigits + pwSymbols

	// Characters that must NEVER appear: ':' (breaks user:pass parsing) plus the
	// set the PR60X previously rejected wholesale ("-_.=+", DAI error 18) and the
	// shell/JSON/glob metacharacters we deliberately keep out for paste-safety.
	// None of these overlap pwSymbols (@#$%); if pwSymbols changes to include one,
	// this guard fails loudly.
	forbidden := ":\"'\\`!*?;&|<>(){}[]~^ -_.=+"

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
		for _, c := range pw {
			if !strings.ContainsRune(allowed, c) {
				t.Fatalf("password %q contains %q outside the allowed pool", pw, c)
			}
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
