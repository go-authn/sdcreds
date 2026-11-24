package sdcreds_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds"
)

// safely runs f and turns a panic into a test failure. A guard that is
// deleted must fail an assertion, not crash the test binary: a crash hides
// every test after it and says nothing about what the guard was for.
func safely(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: the code crashed instead of refusing: %v", name, r)
		}
	}()
	f()
}

func TestArmorWidths(t *testing.T) {
	blob := bytes.Repeat([]byte{7}, 100)
	enc := base64.StdEncoding.EncodeToString(blob)
	for _, w := range []int{0, -1, -79} {
		safely(t, "width", func() {
			if got := sdcreds.Armor(blob, w); got != enc {
				t.Errorf("width %d: %q", w, got)
			}
		})
	}
	safely(t, "width 1", func() {
		if got := sdcreds.Armor(blob, 1); got != strings.Join(strings.Split(enc, ""), "\n")+"\n" {
			t.Errorf("width 1: %q", got)
		}
	})
}

func TestParseMachineIDLengths(t *testing.T) {
	good := strings.Repeat("ab", 16)
	for _, c := range []struct {
		s  string
		ok bool
	}{
		{good, true}, {good + "\n", true},
		{good[:31], false}, {good[:30], false}, {good + "a", false}, {good + "ab", false}, {good + "\n\n", false}, {"", false},
	} {
		safely(t, c.s, func() {
			_, err := sdcreds.ParseMachineID([]byte(c.s))
			if (err == nil) != c.ok || (err != nil && !errors.Is(err, sdcreds.ErrInvalid)) {
				t.Errorf("%q: %v", c.s, err)
			}
		})
	}
}

// ivBlob is a null-key looking blob with the given IV size and room for it.
func ivBlob(iv uint32) []byte {
	p := (32 + int(iv) + 7) &^ 7
	b := make([]byte, p+24+16)
	copy(b, sdcreds.IDNull[:])
	binary.LittleEndian.PutUint32(b[16:], 32)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint32(b[24:], iv)
	binary.LittleEndian.PutUint32(b[28:], 16)
	return b
}

func TestIVSizeBound(t *testing.T) {
	for _, c := range []struct {
		iv uint32
		ok bool
	}{{0, false}, {1, true}, {12, true}, {128, true}, {129, false}, {sdcreds.FieldMax - 1, false}, {sdcreds.FieldMax, false}, {sdcreds.FieldMax + 1, false}, {1 << 31, false}} {
		safely(t, "iv", func() {
			if c.iv > 1<<20 {
				// the blob cannot hold the IV: refused by the length check
				b := ivBlob(0)
				binary.LittleEndian.PutUint32(b[24:], c.iv)
				if _, err := sdcreds.Parse(b); !errors.Is(err, sdcreds.ErrFormat) {
					t.Errorf("iv %d: %v", c.iv, err)
				}
				return
			}
			h, err := sdcreds.Parse(ivBlob(c.iv))
			if c.ok && (err != nil || len(h.IV) != int(c.iv)) {
				t.Errorf("iv %d: %v", c.iv, err)
			}
			if !c.ok && !errors.Is(err, sdcreds.ErrFormat) {
				t.Errorf("iv %d: %v", c.iv, err)
			}
		})
	}
	// A blob whose block or tag size is wrong is refused even with a valid IV.
	for _, off := range []int{20, 28} {
		for _, v := range []uint32{0, 2, 15, 17, sdcreds.FieldMax, sdcreds.FieldMax + 1} {
			if off == 28 && v == 16 || off == 20 && v == 1 {
				continue
			}
			b := ivBlob(12)
			binary.LittleEndian.PutUint32(b[off:], v)
			safely(t, "size", func() {
				if _, err := sdcreds.Parse(b); !errors.Is(err, sdcreds.ErrFormat) {
					t.Errorf("offset %d value %d: %v", off, v, err)
				}
			})
		}
	}
}

func TestEncryptedMaxBoundary(t *testing.T) {
	at := make([]byte, sdcreds.EncryptedMax)
	over := make([]byte, sdcreds.EncryptedMax+1)
	safely(t, "decrypt", func() {
		if _, _, err := sdcreds.Decrypt(at, sdcreds.DecryptOptions{}); errors.Is(err, sdcreds.ErrTooLarge) || err == nil {
			t.Errorf("at the limit: %v", err)
		}
		if _, _, err := sdcreds.Decrypt(over, sdcreds.DecryptOptions{}); !errors.Is(err, sdcreds.ErrTooLarge) {
			t.Errorf("over the limit: %v", err)
		}
	})
	safely(t, "parse", func() {
		if _, err := sdcreds.Parse(at); errors.Is(err, sdcreds.ErrTooLarge) {
			t.Errorf("at the limit: %v", err)
		}
		if _, err := sdcreds.Parse(over); !errors.Is(err, sdcreds.ErrTooLarge) {
			t.Errorf("over the limit: %v", err)
		}
	})
}

// A blob that classify refuses is refused as such, before the scope and
// null-key checks that come first in decrypt_credential_and_warn.
func TestClassifyBeforeScope(t *testing.T) {
	safely(t, "unknown id with a scope", func() {
		_, _, err := sdcreds.Decrypt(make([]byte, 64), sdcreds.DecryptOptions{Scope: scoped(1, "a", fixedMID)})
		var unsup *sdcreds.UnsupportedModeError
		if !errors.As(err, &unsup) {
			t.Errorf("%v", err)
		}
	})
	for _, n := range []int{0, 7, 15, 16, 19} {
		safely(t, "short plaintext", func() {
			_, _, err := sdcreds.Decrypt(craft(make([]byte, n)), sdcreds.DecryptOptions{Timestamp: 1, AllowNull: true})
			if !errors.Is(err, sdcreds.ErrFormat) {
				t.Errorf("%d bytes: %v", n, err)
			}
		})
	}
}

// A blob that classify refuses never reaches the null-key policy.
func TestClassifyBeforePolicy(t *testing.T) {
	for _, n := range []int{0, 1, 15} {
		safely(t, "short", func() {
			_, _, err := sdcreds.Decrypt(make([]byte, n), sdcreds.DecryptOptions{RefuseNull: true})
			if err == nil || errors.Is(err, sdcreds.ErrNullRefused) {
				t.Errorf("%d bytes: %v", n, err)
			}
		})
	}
}

func TestGuardedRefusals(t *testing.T) {
	ok := nullBlob(t)
	safely(t, "parse every prefix", func() {
		for n := 0; n < 48+24+16; n++ {
			if _, err := sdcreds.Parse(ok[:n]); !errors.Is(err, sdcreds.ErrFormat) {
				t.Errorf("prefix %d: %v", n, err)
			}
		}
	})
	// Every header Parse refuses is refused by Decrypt with the same error,
	// and none of them panics.
	for name, b := range map[string][]byte{
		"key size": mutate(ok, 16, 16), "block 0": mutate(ok, 20, 0), "block 2": mutate(ok, 20, 2),
		"iv 0": mutate(ok, 24, 0), "iv huge": mutate(ok, 24, 1<<30), "tag 0": mutate(ok, 28, 0), "tag 12": mutate(ok, 28, 12),
		"short": ok[:40],
	} {
		safely(t, name, func() {
			if _, _, err := sdcreds.Decrypt(b, sdcreds.DecryptOptions{AllowNull: true}); !errors.Is(err, sdcreds.ErrFormat) {
				t.Errorf("%s: %v", name, err)
			}
		})
	}
	sc, err := sdcreds.Encrypt([]byte("x"), sdcreds.EncryptOptions{Key: sdcreds.IDHostScoped, HostKey: staticKey, Timestamp: 1, Scope: scoped(1, "a", fixedMID)})
	if err != nil {
		t.Fatal(err)
	}
	safely(t, "scoped without scope", func() {
		if _, _, err := sdcreds.Decrypt(sc, sdcreds.DecryptOptions{HostKey: staticKey}); !errors.Is(err, sdcreds.ErrScope) {
			t.Errorf("%v", err)
		}
	})
	for _, f := range []byte{0, 1, 3, 15} {
		b := append([]byte(nil), sc...)
		b[48] = f
		var unsup *sdcreds.UnsupportedModeError
		safely(t, "flags", func() {
			if _, _, err := sdcreds.Decrypt(b, sdcreds.DecryptOptions{HostKey: staticKey, Scope: scoped(1, "a", fixedMID)}); !errors.As(err, &unsup) {
				t.Errorf("flags %d: %v", f, err)
			}
		})
	}
	safely(t, "encrypt scoped without scope", func() {
		_, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: sdcreds.IDHostScoped, HostKey: staticKey, Timestamp: 1})
		if !errors.Is(err, sdcreds.ErrInvalid) {
			t.Errorf("%v", err)
		}
	})
	for _, id := range []sdcreds.KeyID{sdcreds.IDHost, sdcreds.IDHostScoped} {
		safely(t, "encrypt without host key", func() {
			_, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: id, Timestamp: 1, Scope: scoped(1, "a", fixedMID)})
			if !errors.Is(err, sdcreds.ErrInvalid) {
				t.Errorf("%v", err)
			}
		})
		safely(t, "decrypt without host key", func() {
			b, _ := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: id, HostKey: staticKey, Timestamp: 1, Scope: scoped(1, "a", fixedMID)})
			var sc *sdcreds.Scope
			if id == sdcreds.IDHostScoped {
				sc = scoped(1, "a", fixedMID)
			}
			_, _, err := sdcreds.Decrypt(b, sdcreds.DecryptOptions{Scope: sc})
			if !errors.Is(err, sdcreds.ErrInvalid) {
				t.Errorf("%v", err)
			}
		})
	}
}

// The metadata sizes on both sides of each bound (cu.c:1664-1672).
func TestMetadataSizeEdges(t *testing.T) {
	inf := sdcreds.Infinity
	for _, c := range []struct {
		name string
		pt   []byte
		ok   bool
	}{
		{"23 bytes", make([]byte, 23), false},
		{"24 bytes, no name", meta(inf, inf, 0, "", ""), true},
		{"name 1 fits 24", meta(inf, inf, 1, "a", ""), true},
		{"name 4 fits 24", meta(inf, inf, 4, "abcd", ""), true},
		{"name 5 needs 32", append(meta(inf, inf, 5, "", ""), 0), false},
		{"name 5 in 32", meta(inf, inf, 5, "abcde", ""), true},
		{"name 4 claimed in 16 bytes", meta(inf, inf, 4, "", "")[:16], false},
		{"name 255", meta(inf, inf, 255, strings.Repeat("a", 255), ""), true},
		{"name 256", meta(inf, inf, 256, strings.Repeat("a", 256), ""), false},
		{"name 1<<20 claimed", meta(inf, inf, 1<<20, "", ""), false},
		{"name 4G-1 claimed", meta(inf, inf, 1<<32-1, "", ""), false},
	} {
		safely(t, c.name, func() {
			_, _, err := sdcreds.Decrypt(craft(c.pt), sdcreds.DecryptOptions{Timestamp: 1, AllowNull: true})
			if c.ok != (err == nil) || (!c.ok && !errors.Is(err, sdcreds.ErrFormat)) {
				t.Errorf("%s: %v", c.name, err)
			}
		})
	}
}
