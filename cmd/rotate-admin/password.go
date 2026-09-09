package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Character classes for generated passwords.
//
// The symbol set is constrained by the DEVICE, not just by shell/JSON safety.
// The PR60X backend (gf-configd / libgf-dai) enforces a password special-char
// whitelist and rejects anything outside it with DAI error 18: "Password does
// not allow configuring other than allowed special characters." Empirically the
// earlier set "-_.=+" was rejected wholesale (none of - _ . = + are allowed),
// which stalled a rotation. The device's own web UI validates the password field
// against the class [!@#$%^&*] (the smallest of several allowed classes seen in
// the shipped SPA bundle main.e919b37a.js; the larger classes are supersets), so
// every character below is inside that whitelist and accepted by setAdminPassword.
//
// Within that whitelist we further pick @ # $ % — they carry no ':' (which breaks
// user:pass parsing), no quotes/backslash/backtick, and none of the glob/redirect
// metacharacters * ? & | < > ( ) [ ] { } ~ ^ ! or space. The password is only ever
// consumed programmatically (Vault API → exporters / cert-operator / terraform),
// never typed, but keeping it paste-safe costs nothing.
const (
	pwLowers  = "abcdefghijklmnopqrstuvwxyz"
	pwUppers  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	pwDigits  = "0123456789"
	pwSymbols = "@#$%"
)

// generatePassword returns a cryptographically strong password of the given
// length that is guaranteed to contain at least one lower-case letter, one
// upper-case letter, one digit and one safe symbol, and to contain no ':' or
// shell/JSON-hostile characters. A length below 8 is bumped to a safe default.
func generatePassword(length int) (string, error) {
	if length < 8 {
		length = 20
	}

	classes := []string{pwLowers, pwUppers, pwDigits, pwSymbols}
	all := pwLowers + pwUppers + pwDigits + pwSymbols

	buf := make([]byte, 0, length)

	// Guarantee one character from each class so the result always satisfies a
	// upper/lower/digit/symbol complexity policy.
	for _, cls := range classes {
		c, err := randByte(cls)
		if err != nil {
			return "", err
		}
		buf = append(buf, c)
	}

	// Fill the remainder from the combined pool.
	for len(buf) < length {
		c, err := randByte(all)
		if err != nil {
			return "", err
		}
		buf = append(buf, c)
	}

	// Shuffle so the guaranteed characters are not always in the first four
	// positions (a Fisher–Yates over crypto/rand).
	if err := shuffle(buf); err != nil {
		return "", err
	}

	return string(buf), nil
}

// randByte returns a uniformly random byte from set using crypto/rand.
func randByte(set string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(set))))
	if err != nil {
		return 0, fmt.Errorf("random selection: %w", err)
	}
	return set[n.Int64()], nil
}

// shuffle performs an in-place Fisher–Yates shuffle using crypto/rand.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("shuffle: %w", err)
		}
		jj := int(j.Int64())
		b[i], b[jj] = b[jj], b[i]
	}
	return nil
}
