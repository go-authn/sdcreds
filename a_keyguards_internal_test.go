package sdcreds

import (
	"bytes"
	"errors"
	"testing"
)

type fixedKey []byte

func (k fixedKey) HostKey() ([]byte, error) { return append([]byte{}, k...), nil }

// The AES key derived from the host key, and the unscoped hash a scoped key
// is derived from, are wiped once Encrypt and Decrypt return.
func TestDerivedKeyBuffersAreWiped(t *testing.T) {
	var seen [][]byte
	keyBuffer = func(b []byte) {
		allZero := true
		for _, c := range b {
			if c != 0 {
				allZero = false
			}
		}
		if allZero {
			t.Errorf("seam saw a key buffer that is already zero")
		}
		seen = append(seen, b)
	}
	t.Cleanup(func() { keyBuffer = func([]byte) {} })

	hk := fixedKey("0123456789abcdef0123456789abcdef0123456789abcdef")
	mid, err := ParseMachineID([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("panicked: %v", r)
		}
	}()
	for _, c := range []struct {
		name string
		o    EncryptOptions
		want int // buffers derived: 2 when scoped (hash, then HMAC)
	}{
		{"null", EncryptOptions{Key: IDNull, Name: "n"}, 1},
		{"host", EncryptOptions{Key: IDHost, HostKey: hk, Name: "n"}, 1},
		{"scoped", EncryptOptions{Key: IDHostScoped, HostKey: hk, Name: "n", Scope: &Scope{UID: 7, Username: "u", MachineID: mid}}, 2},
	} {
		seen = nil
		blob, err := Encrypt([]byte("secret"), c.o)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(seen) != c.want {
			t.Fatalf("%s encrypt: %d key buffers seen, want %d", c.name, len(seen), c.want)
		}
		for i, b := range seen {
			if !isZero(b) {
				t.Errorf("%s encrypt: key buffer %d not wiped: %x", c.name, i, b)
			}
		}
		seen = nil
		if _, _, err := Decrypt(blob, DecryptOptions{HostKey: hk, Scope: c.o.Scope, AllowNull: true}); err != nil {
			t.Fatalf("%s decrypt: %v", c.name, err)
		}
		if len(seen) != c.want {
			t.Fatalf("%s decrypt: %d key buffers seen, want %d", c.name, len(seen), c.want)
		}
		for i, b := range seen {
			if !isZero(b) {
				t.Errorf("%s decrypt: key buffer %d not wiped: %x", c.name, i, b)
			}
		}
	}
}

// attempt runs f and turns a panic into a failed assertion: a guard whose
// removal makes the code crash is then held by an assertion, not by luck.
func attempt(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: panicked: %v", what, r)
		}
	}()
	f()
}

// Guards that were held only by a crash when they were deleted.
func TestKeyGuardsAreHeldByAssertions(t *testing.T) {
	hk1 := fixedKey("0123456789abcdef0123456789abcdef0123456789abcdef")
	hk2 := fixedKey("fedcba9876543210fedcba9876543210fedcba9876543210")
	mid, _ := ParseMachineID([]byte("0123456789abcdef0123456789abcdef"))
	scope := &Scope{UID: 7, Username: "u", MachineID: mid}

	// A host-key credential needs its host key: another one is refused.
	attempt(t, "wrong host key", func() {
		blob, err := Encrypt([]byte("x"), EncryptOptions{Key: IDHost, HostKey: hk1, Name: "n"})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Decrypt(blob, DecryptOptions{HostKey: hk2}); !errors.Is(err, ErrAuth) {
			t.Errorf("decrypt with another host key: %v, want ErrAuth", err)
		}
	})
	// Without Options.Rand the IV is random: two encryptions differ.
	attempt(t, "default random source", func() {
		a, errA := Encrypt([]byte("x"), EncryptOptions{Key: IDNull, Name: "n", Timestamp: 1})
		b, errB := Encrypt([]byte("x"), EncryptOptions{Key: IDNull, Name: "n", Timestamp: 1})
		if errA != nil || errB != nil {
			t.Fatal(errA, errB)
		}
		if bytes.Equal(a, b) {
			t.Error("two encryptions with the default source are identical")
		}
	})
	// A scoped credential is decrypted with its scope, and not without it.
	attempt(t, "scoped decrypt", func() {
		blob, err := Encrypt([]byte("x"), EncryptOptions{Key: IDHostScoped, HostKey: hk1, Name: "n", Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Decrypt(blob, DecryptOptions{HostKey: hk1, Scope: scope}); err != nil {
			t.Errorf("scoped decrypt with its scope: %v", err)
		}
		if _, _, err := Decrypt(blob, DecryptOptions{HostKey: hk1}); err == nil {
			t.Error("scoped decrypt without a scope succeeded")
		}
	})
}

func isZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
