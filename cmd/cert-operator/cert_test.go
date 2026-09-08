package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// selfSigned makes a throwaway leaf certificate for the parsing/compare tests.
func selfSigned(t *testing.T, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func pemOf(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// leafFromPEM must return the FIRST cert of a bundle - a cert-manager tls.crt is
// leaf then intermediates, and pushing the intermediate as the leaf would serve
// the wrong identity.
func TestLeafFromPEM_PicksFirst(t *testing.T) {
	leaf := selfSigned(t, "leaf")
	inter := selfSigned(t, "intermediate")
	bundle := append(pemOf(leaf), pemOf(inter)...)

	got, err := leafFromPEM(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject.CommonName != "leaf" {
		t.Fatalf("got CN %q, want leaf", got.Subject.CommonName)
	}
}

func TestLeafFromPEM_NoCert(t *testing.T) {
	if _, err := leafFromPEM([]byte("not a pem")); err == nil {
		t.Fatal("expected an error for input with no CERTIFICATE block")
	}
}

// fingerprint must equal the SHA-256 of the DER, so a compare against
// `openssl x509 -fingerprint -sha256` (and against the served cert) agrees.
func TestFingerprint(t *testing.T) {
	c := selfSigned(t, "fp")
	sum := sha256.Sum256(c.Raw)
	if got, want := fingerprint(c), hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("fingerprint=%s want %s", got, want)
	}
	// Two different certs must not collide.
	if fingerprint(c) == fingerprint(selfSigned(t, "other")) {
		t.Fatal("distinct certs produced the same fingerprint")
	}
}

// concatPEM must guarantee a separator so the PR60X's key-then-cert server.pem
// does not merge the two armor lines.
func TestConcatPEM_InsertsNewline(t *testing.T) {
	got := concatPEM([]byte("-----A-----"), []byte("-----B-----"))
	if !bytes.Equal(got, []byte("-----A-----\n-----B-----")) {
		t.Fatalf("got %q", got)
	}
	// An existing trailing newline is not doubled.
	got = concatPEM([]byte("a\n"), []byte("b"))
	if !bytes.Equal(got, []byte("a\nb")) {
		t.Fatalf("got %q", got)
	}
}

func TestDeriveAddr(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://192.0.2.3", "192.0.2.3:443"},
		{"http://192.0.2.3", "192.0.2.3:443"},
		{"https://sw2.example.com:8443", "sw2.example.com:443"},
	} {
		if got := deriveAddr(tc.in); got != tc.want {
			t.Errorf("deriveAddr(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestEnvBool(t *testing.T) {
	t.Setenv("CO_TEST_FLAG", "true")
	if !envBool("CO_TEST_FLAG", false) {
		t.Error("true should parse true")
	}
	t.Setenv("CO_TEST_FLAG", "off")
	if envBool("CO_TEST_FLAG", true) {
		t.Error("off should parse false")
	}
	if !envBool("CO_TEST_UNSET", true) {
		t.Error("unset should return the default")
	}
}
