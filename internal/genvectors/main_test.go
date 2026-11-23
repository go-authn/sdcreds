package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/internal/vecspec"
)

func TestClassify(t *testing.T) {
	for stderr, want := range map[string]vecspec.Class{
		"Embedded credential name 'foo' does not match filename 'bar', refusing.": vecspec.NameMismatch,
		"Credential's time passed, refusing.":                                     vecspec.Expired,
		"Encrypted file is scoped to a user, but no user selected.":               vecspec.Scope,
		"Decryption failed (Bad message)":                                         vecspec.Auth,
		"Encrypted file too short.":                                               vecspec.Format,
		"Unexpected something":                                                    vecspec.Format,
		"Failed to read encrypted credential":                                     vecspec.Format,
		"something nobody expected":                                               "",
	} {
		if got := classify(stderr); got != want {
			t.Errorf("%q: %q, want %q", stderr, got, want)
		}
	}
}

func TestWithKey(t *testing.T) {
	if withKey("null") != "null" || withKey("host") != "host" || withKey("host-scoped") != "host" {
		t.Fatal("with-key mapping")
	}
	if p := ptr("x"); *p != "x" {
		t.Fatal("ptr")
	}
}

func TestTamper(t *testing.T) {
	dir := t.TempDir()
	blob, err := sdcreds.Encrypt([]byte("payload"), sdcreds.EncryptOptions{Key: sdcreds.IDNull, Timestamp: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "base.cred"), []byte(sdcreds.Armor(blob, sdcreds.ArmorWidth)), 0o644); err != nil {
		t.Fatal(err)
	}
	for tamper, check := range map[string]func(got []byte) bool{
		"flip-iv":         func(g []byte) bool { return len(g) == len(blob) && g[32] == blob[32]^1 },
		"flip-ciphertext": func(g []byte) bool { return len(g) == len(blob) && g[len(g)-17] == blob[len(g)-17]^1 },
		"flip-tag":        func(g []byte) bool { return len(g) == len(blob) && g[len(g)-1] == blob[len(g)-1]^1 },
		"truncate-tag":    func(g []byte) bool { return len(g) == len(blob)-1 },
		"truncate-header": func(g []byte) bool { return len(g) == 20 },
	} {
		v := vecspec.Vector{File: tamper + ".cred", Tamper: tamper}
		if err := doTamper(dir, "base.cred", &v); err != nil {
			t.Fatal(err)
		}
		text, err := os.ReadFile(filepath.Join(dir, v.File))
		if err != nil {
			t.Fatal(err)
		}
		got, err := sdcreds.Unarmor(text)
		if err != nil || !check(got) {
			t.Errorf("%s: %v", tamper, err)
		}
		// Only the intended byte differs.
		if len(got) == len(blob) && bytes.Equal(got, blob) {
			t.Errorf("%s: the blob is unchanged", tamper)
		}
	}
	if err := doTamper(dir, "missing.cred", &vecspec.Vector{File: "x"}); err == nil {
		t.Error("missing base accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.cred"), []byte("!!"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := doTamper(dir, "bad.cred", &vecspec.Vector{File: "x"}); err == nil {
		t.Error("bad base64 accepted")
	}
}
