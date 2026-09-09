package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Character classes for generated passwords.
//
// The symbol set is deliberately tiny and conservative: it contains NO ':'
// (which breaks user:pass parsing and some device forms) and none of the shell
// or JSON metacharacters — no quotes, backslash, $, backtick, and none of
// ! * ? ; & | < > ( ) { } [ ] # ~ % ^ or space. Everything here is safe to
// paste into a shell unquoted, embed in a JSON string, and hand to the device
// RPC without escaping.
const (
	pwLowers  = "abcdefghijklmnopqrstuvwxyz"
	pwUppers  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	pwDigits  = "0123456789"
	pwSymbols = "-_.=+"
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
