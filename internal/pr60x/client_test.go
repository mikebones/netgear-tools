package pr60x

import (
	"os"
	"regexp"
	"testing"
)

// Every JSON-RPC method on this device is lowerCamelCase. A mechanical rename
// that exported the Go methods once rewrote the method-name STRING LITERALS
// too ("getDeviceInfo" -> "GetDeviceInfo"), which the device answers with
// -32601 method-not-found. Nothing else caught it: the code compiled, most
// calls still worked, and only the handful of methods whose Go name happened
// to equal their RPC name broke.
//
// This guards the whole class of mistake by reading the source rather than
// the API surface, so it also covers methods added later.
func TestRPCMethodNamesAreLowerCamelCase(t *testing.T) {
	src, err := os.ReadFile("client.go")
	if err != nil {
		t.Fatalf("read client.go: %v", err)
	}

	// Matches c.Call("x", ...), c.CallResult("x", ...) and c.post("x", ...).
	call := regexp.MustCompile(`c\.(?:Call|CallResult|post)\("([A-Za-z][A-Za-z0-9]*)"`)
	matches := call.FindAllSubmatch(src, -1)
	if len(matches) == 0 {
		t.Fatal("found no RPC call sites - has the call convention changed?")
	}

	seen := map[string]bool{}
	for _, m := range matches {
		name := string(m[1])
		if seen[name] {
			continue
		}
		seen[name] = true
		if c := name[0]; c < 'a' || c > 'z' {
			t.Errorf("RPC method %q must start lowercase; the device answers -32601 otherwise", name)
		}
	}
	t.Logf("checked %d distinct RPC method names", len(seen))
}

// The double-wrap set is keyed by RPC method name too, so it has the same
// exposure to a careless rename.
func TestDoubleWrappedKeysAreLowerCamelCase(t *testing.T) {
	for name := range doubleWrapped {
		if name == "" {
			t.Fatal("empty key in doubleWrapped")
		}
		if c := name[0]; c < 'a' || c > 'z' {
			t.Errorf("doubleWrapped key %q must start lowercase", name)
		}
	}
}
