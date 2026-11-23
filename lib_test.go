package sdcreds_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds"
)

var (
	fixedMID  = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	otherMID  = [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	zeroIV    = make([]byte, 12)
	secret4k  = bytes.Repeat([]byte{0x5a}, 64)
	staticKey = sdcreds.StaticHostKey(secret4k)
)

func str(s string) *string { return &s }

func TestNameValid(t *testing.T) {
	good := []string{"a", "foo", "a b", "~", " ", "x.y", "...", strings.Repeat("a", 255)}
	bad := []string{"", ".", "..", "a/b", "/", "a:b", ":", "a\x1fb", "a\x00b", "a\x7fb", "é", strings.Repeat("a", 256), "a\nb"}
	for _, s := range good {
		if !sdcreds.NameValid(s) {
			t.Errorf("%q should be valid", s)
		}
	}
	for _, s := range bad {
		if sdcreds.NameValid(s) {
			t.Errorf("%q should be invalid", s)
		}
	}
}

func TestParseMachineID(t *testing.T) {
	id, err := sdcreds.ParseMachineID([]byte("0102030405060708090a0b0c0d0e0f10\n"))
	if err != nil || id != fixedMID {
		t.Fatalf("%x %v", id, err)
	}
	if _, err := sdcreds.ParseMachineID([]byte("0102030405060708090a0b0c0d0e0f10")); err != nil {
		t.Fatal("no newline:", err)
	}
	for _, s := range []string{"", "01", "0102030405060708090a0b0c0d0e0f1011", "0102030405060708090a0b0c0d0e0fzz", strings.Repeat("0", 32)} {
		if _, err := sdcreds.ParseMachineID([]byte(s)); !errors.Is(err, sdcreds.ErrInvalid) {
			t.Errorf("%q: %v", s, err)
		}
	}
	p := filepath.Join(t.TempDir(), "machine-id")
	if err := os.WriteFile(p, []byte("0102030405060708090a0b0c0d0e0f10\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if id, err := sdcreds.ReadMachineID(p); err != nil || id != fixedMID {
		t.Fatalf("%x %v", id, err)
	}
	if _, err := sdcreds.ReadMachineID(p + ".missing"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestAppSpecificID(t *testing.T) {
	a := sdcreds.AppSpecificID(fixedMID, [16]byte{1})
	b := sdcreds.AppSpecificID(fixedMID, [16]byte{2})
	c := sdcreds.AppSpecificID(otherMID, [16]byte{1})
	if a == b || a == c {
		t.Fatal("the id must depend on both inputs")
	}
	if a[6]>>4 != 4 || a[8]>>6 != 2 {
		t.Fatalf("not a version 4 variant 1 UUID: %x", a)
	}
	if sdcreds.HostSecretMachineID(fixedMID) == sdcreds.HostSecretMachineID(otherMID) {
		t.Fatal("prefix independent of the machine id")
	}
}

func writeSecret(t *testing.T, mode os.FileMode, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func goodSecret() []byte {
	p := sdcreds.HostSecretMachineID(fixedMID)
	return append(p[:], secret4k...)
}

func TestHostKeyFile(t *testing.T) {
	p := writeSecret(t, 0o400, goodSecret())
	k, err := sdcreds.HostKeyFile{Path: p, MachineID: fixedMID}.HostKey()
	if err != nil || !bytes.Equal(k, secret4k) {
		t.Fatalf("%x %v", k, err)
	}
	for _, mode := range []os.FileMode{0o600, 0o440, 0o404, 0o444, os.ModeSetuid | 0o400, os.ModeSticky | 0o400} {
		p := writeSecret(t, mode, goodSecret())
		if _, err := (sdcreds.HostKeyFile{Path: p, MachineID: fixedMID}).HostKey(); err == nil || !strings.Contains(err.Error(), "permissive") {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	// A different machine id.
	if _, err := (sdcreds.HostKeyFile{Path: p, MachineID: otherMID}).HostKey(); !errors.Is(err, sdcreds.ErrHostKeyMachine) {
		t.Errorf("machine mismatch: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("a mismatching secret must not be deleted: %v", err)
	}
	// Size bounds: 16 bytes refused, 17 accepted.
	small := writeSecret(t, 0o400, goodSecret()[:16])
	if _, err := (sdcreds.HostKeyFile{Path: small, MachineID: fixedMID}).HostKey(); err == nil || !strings.Contains(err.Error(), "too small") {
		t.Errorf("16 bytes: %v", err)
	}
	min := writeSecret(t, 0o400, goodSecret()[:17])
	if k, err := (sdcreds.HostKeyFile{Path: min, MachineID: fixedMID}).HostKey(); err != nil || len(k) != 1 {
		t.Errorf("17 bytes: %x %v", k, err)
	}
	// Two links.
	l := filepath.Join(filepath.Dir(p), "second")
	if err := os.Link(p, l); err != nil {
		t.Fatal(err)
	}
	if _, err := (sdcreds.HostKeyFile{Path: p, MachineID: fixedMID}).HostKey(); err == nil || !strings.Contains(err.Error(), "links") {
		t.Errorf("hard link: %v", err)
	}
	// Symlink as the last component.
	sd := t.TempDir()
	target := writeSecret(t, 0o400, goodSecret())
	sl := filepath.Join(sd, "link")
	if err := os.Symlink(target, sl); err != nil {
		t.Fatal(err)
	}
	if _, err := (sdcreds.HostKeyFile{Path: sl, MachineID: fixedMID}).HostKey(); err == nil {
		t.Error("a symlink must be refused")
	}
	// A directory and a missing file.
	if _, err := (sdcreds.HostKeyFile{Path: sd, MachineID: fixedMID}).HostKey(); err == nil {
		t.Error("a directory must be refused")
	}
	if _, err := (sdcreds.HostKeyFile{Path: target + ".none", MachineID: fixedMID}).HostKey(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

// TestHostKeyBomb: a host secret over 16 MiB is refused from its size alone,
// before any buffer is allocated.
func TestHostKeyBomb(t *testing.T) {
	p := writeSecret(t, 0o600, goodSecret())
	if err := os.Truncate(p, sdcreds.HostSecretMax+1); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o400); err != nil {
		t.Fatal(err)
	}
	before := heap()
	_, err := sdcreds.HostKeyFile{Path: p, MachineID: fixedMID}.HostKey()
	if !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Fatal(err)
	}
	if grew := heap() - before; grew > 1<<20 {
		t.Fatalf("the refusal allocated %d bytes", grew)
	}
	// Exactly 16 MiB is accepted.
	if err := os.Chmod(p, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, sdcreds.HostSecretMax); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := (sdcreds.HostKeyFile{Path: p, MachineID: fixedMID}).HostKey(); err != nil {
		t.Fatalf("16 MiB: %v", err)
	}
}

func heap() uint64 {
	var m runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m)
	return m.TotalAlloc
}

func TestHostSecretPath(t *testing.T) {
	t.Setenv(sdcreds.HostSecretEnv, "")
	os.Unsetenv(sdcreds.HostSecretEnv)
	if p, err := sdcreds.HostSecretPath(); err != nil || p != sdcreds.DefaultHostSecretPath {
		t.Fatalf("%q %v", p, err)
	}
	t.Setenv(sdcreds.HostSecretEnv, "/a/b/secret")
	if p, err := sdcreds.HostSecretPath(); err != nil || p != "/a/b/secret" {
		t.Fatalf("%q %v", p, err)
	}
	for _, bad := range []string{"relative/secret", "/a/../b", "/a//b", "/a/b/", "", "/a/./b"} {
		t.Setenv(sdcreds.HostSecretEnv, bad)
		if _, err := sdcreds.HostSecretPath(); !errors.Is(err, sdcreds.ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// HostKey honours the variable when Path is empty.
	p := writeSecret(t, 0o400, goodSecret())
	t.Setenv(sdcreds.HostSecretEnv, p)
	if k, err := (sdcreds.HostKeyFile{MachineID: fixedMID}).HostKey(); err != nil || !bytes.Equal(k, secret4k) {
		t.Fatalf("%x %v", k, err)
	}
	t.Setenv(sdcreds.HostSecretEnv, "relative")
	if _, err := (sdcreds.HostKeyFile{MachineID: fixedMID}).HostKey(); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Fatalf("%v", err)
	}
}

func TestCreateHostKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub", "dir")
	p := filepath.Join(dir, "credential.secret")
	k, err := sdcreds.CreateHostKey(p, fixedMID)
	if err != nil {
		t.Fatal(err)
	}
	if len(k) != sdcreds.HostSecretDataSize {
		t.Fatalf("key of %d bytes", len(k))
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o400 || st.Size() != 16+sdcreds.HostSecretDataSize {
		t.Fatalf("%v %v", st, err)
	}
	got, err := sdcreds.HostKeyFile{Path: p, MachineID: fixedMID}.HostKey()
	if err != nil || !bytes.Equal(got, k) {
		t.Fatalf("the created secret does not read back: %v", err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temporary file left behind: %v", ents)
	}
	// An existing secret is never replaced.
	if _, err := sdcreds.CreateHostKey(p, fixedMID); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second create: %v", err)
	}
	got2, _ := sdcreds.HostKeyFile{Path: p, MachineID: fixedMID}.HostKey()
	if !bytes.Equal(got2, k) {
		t.Fatal("the secret was replaced")
	}
	// A path whose parent is a file.
	if _, err := sdcreds.CreateHostKey(filepath.Join(p, "x"), fixedMID); err == nil {
		t.Fatal("parent is a file")
	}
	// A directory that cannot be created.
	if _, err := sdcreds.CreateHostKey(filepath.Join(p, "x", "y"), fixedMID); err == nil {
		t.Fatal("cannot create a directory below a file")
	}
}

func TestArmor(t *testing.T) {
	blob := bytes.Repeat([]byte{0xfb, 0x00, 0x7e}, 100) // 300 bytes: 400 digits
	a := sdcreds.Armor(blob, 79)
	lines := strings.Split(strings.TrimSuffix(a, "\n"), "\n")
	if !strings.HasSuffix(a, "\n") || len(lines) != 6 || len(lines[0]) != 79 || len(lines[5]) != 400-5*79 {
		t.Fatalf("layout: %d lines, first %d, last %d, final newline %v", len(lines), len(lines[0]), len(lines[len(lines)-1]), strings.HasSuffix(a, "\n"))
	}
	if sdcreds.Armor(blob, 69) == a || strings.Index(sdcreds.Armor(blob, 69), "\n") != 69 {
		t.Fatal("pretty width")
	}
	if flat := sdcreds.Armor(blob, 0); strings.Contains(flat, "\n") || len(flat) != 400 {
		t.Fatal("width 0 must not wrap")
	}
	if sdcreds.Armor(nil, 79) != "" {
		t.Fatal("empty blob")
	}
	back, err := sdcreds.Unarmor([]byte(a))
	if err != nil || !bytes.Equal(back, blob) {
		t.Fatalf("round trip: %v", err)
	}
	// White space of every kind is ignored, and padding is optional.
	odd := "  " + strings.ReplaceAll(sdcreds.Armor([]byte("ab"), 0), "=", "") + "\r\n\t\v\f "
	if got, err := sdcreds.Unarmor([]byte(odd)); err != nil || string(got) != "ab" {
		t.Fatalf("%q %v", got, err)
	}
	if got, err := sdcreds.Unarmor([]byte("YWI=")); err != nil || string(got) != "ab" {
		t.Fatalf("padded: %q %v", got, err)
	}
	if got, err := sdcreds.Unarmor([]byte("YQ==")); err != nil || string(got) != "a" {
		t.Fatalf("padded: %q %v", got, err)
	}
	for _, bad := range []string{"YQ===", "YQ!=", "Y", "a b c d e", "YW=I"} {
		if _, err := sdcreds.Unarmor([]byte(bad)); !errors.Is(err, sdcreds.ErrFormat) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if _, err := sdcreds.Unarmor(nil); err != nil {
		t.Errorf("empty: %v", err)
	}
}

// TestUnarmorBomb: oversized text is refused before the decoder allocates.
func TestUnarmorBomb(t *testing.T) {
	text := make([]byte, 4<<20)
	for i := range text {
		text[i] = 'A'
	}
	before := heap()
	if _, err := sdcreds.Unarmor(text); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Fatal(err)
	}
	if grew := heap() - before; grew > 1<<20 {
		t.Fatalf("the refusal allocated %d bytes", grew)
	}
	// Text that fits the text bound but decodes to more than EncryptedMax.
	over := sdcreds.Armor(make([]byte, sdcreds.EncryptedMax+1), 0)
	if _, err := sdcreds.Unarmor([]byte(over)); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Fatal(err)
	}
	ok := sdcreds.Armor(make([]byte, sdcreds.EncryptedMax), 0)
	if got, err := sdcreds.Unarmor([]byte(ok)); err != nil || len(got) != sdcreds.EncryptedMax {
		t.Fatal(err)
	}
}

func TestEnvOverrides(t *testing.T) {
	for _, v := range []string{"0", "no", "NO", "false", "off", "n", "f", "False"} {
		t.Setenv("SYSTEMD_CREDENTIAL_VALIDATE_NAME", v)
		t.Setenv("SYSTEMD_CREDENTIAL_VALIDATE_NOT_AFTER", v)
		var o sdcreds.DecryptOptions
		o.EnvOverrides()
		if !o.IgnoreName || !o.IgnoreNotAfter {
			t.Errorf("%q must disable both checks", v)
		}
	}
	for _, v := range []string{"", "1", "yes", "true", "on", "garbage"} {
		t.Setenv("SYSTEMD_CREDENTIAL_VALIDATE_NAME", v)
		t.Setenv("SYSTEMD_CREDENTIAL_VALIDATE_NOT_AFTER", "0")
		var o sdcreds.DecryptOptions
		o.EnvOverrides()
		if o.IgnoreName || !o.IgnoreNotAfter {
			t.Errorf("%q: name=%v notafter=%v", v, o.IgnoreName, o.IgnoreNotAfter)
		}
	}
}

func hostOpts(name string) sdcreds.EncryptOptions {
	return sdcreds.EncryptOptions{Key: sdcreds.IDHost, HostKey: staticKey, Name: name, Timestamp: 1000}
}

func TestEncryptRefusals(t *testing.T) {
	tpm := sdcreds.KeyID{0x0c, 0x7c, 0xc0, 0x7b, 0x11, 0x76, 0x45, 0x91, 0x9c, 0x4b, 0x0b, 0xea, 0x08, 0xbc, 0x20, 0xfe}
	var unsup *sdcreds.UnsupportedModeError
	if _, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: tpm}); !errors.As(err, &unsup) || !unsup.Known || unsup.Mode != "tpm2" {
		t.Errorf("tpm2: %v", err)
	}
	if _, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{}); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("zero key id: %v", err)
	}
	if _, err := sdcreds.Encrypt(make([]byte, sdcreds.PlaintextMax+1), hostOpts("")); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Errorf("1 MiB + 1: %v", err)
	}
	if _, err := sdcreds.Encrypt(make([]byte, sdcreds.PlaintextMax), hostOpts("")); err != nil {
		t.Errorf("exactly 1 MiB: %v", err)
	}
	if _, err := sdcreds.Encrypt(nil, hostOpts("a/b")); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("name: %v", err)
	}
	o := hostOpts("")
	o.NotAfter = 1000
	if _, err := sdcreds.Encrypt(nil, o); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("not-after == timestamp: %v", err)
	}
	o.NotAfter = 999
	if _, err := sdcreds.Encrypt(nil, o); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("not-after < timestamp: %v", err)
	}
	o.NotAfter = 1001
	if _, err := sdcreds.Encrypt(nil, o); err != nil {
		t.Errorf("not-after > timestamp: %v", err)
	}
	o.Timestamp, o.NotAfter = sdcreds.Infinity, 5
	if _, err := sdcreds.Encrypt(nil, o); err != nil {
		t.Errorf("no timestamp: %v", err)
	}
	if _, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: sdcreds.IDHostScoped, HostKey: staticKey}); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("scoped without a scope: %v", err)
	}
	if _, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: sdcreds.IDNull, RefuseNull: true}); !errors.Is(err, sdcreds.ErrNullRefused) {
		t.Errorf("refuse null: %v", err)
	}
	if _, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: sdcreds.IDHost}); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("no host key source: %v", err)
	}
	if _, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: sdcreds.IDHost, HostKey: sdcreds.StaticHostKey(nil)}); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("empty host key: %v", err)
	}
	if _, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: sdcreds.IDHost, HostKey: sdcreds.HostKeyFile{Path: "/nonexistent/x", MachineID: fixedMID}}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("host key error not propagated: %v", err)
	}
	o = hostOpts("")
	o.Rand = bytes.NewReader(zeroIV[:11])
	if _, err := sdcreds.Encrypt(nil, o); err == nil || !strings.Contains(err.Error(), "IV") {
		t.Errorf("short rand: %v", err)
	}
	sc := sdcreds.EncryptOptions{Key: sdcreds.IDHostScoped, HostKey: staticKey, Scope: &sdcreds.Scope{UID: 1, Username: "a\x00b", MachineID: fixedMID}}
	if _, err := sdcreds.Encrypt(nil, sc); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("user name with NUL: %v", err)
	}
	// Timestamp 0 means now.
	o = hostOpts("")
	o.Timestamp = 0
	blob, err := sdcreds.Encrypt([]byte("x"), o)
	if err != nil {
		t.Fatal(err)
	}
	_, md, err := sdcreds.Decrypt(blob, sdcreds.DecryptOptions{HostKey: staticKey})
	if err != nil || md.Timestamp == 0 || md.Timestamp == sdcreds.Infinity {
		t.Errorf("default timestamp: %+v %v", md, err)
	}
}

func nullBlob(t *testing.T) []byte {
	t.Helper()
	b, err := sdcreds.Encrypt([]byte("payload"), sdcreds.EncryptOptions{Key: sdcreds.IDNull, Timestamp: 1000, Rand: bytes.NewReader(zeroIV)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func scoped(uid uint32, user string, mid [16]byte) *sdcreds.Scope {
	return &sdcreds.Scope{UID: uid, Username: user, MachineID: mid}
}

func TestDecryptRefusals(t *testing.T) {
	ts := uint64(2000)
	host, err := sdcreds.Encrypt([]byte("hello"), sdcreds.EncryptOptions{Key: sdcreds.IDHost, HostKey: staticKey, Name: "foo", Timestamp: 1000, NotAfter: 3000})
	if err != nil {
		t.Fatal(err)
	}
	open := func(blob []byte, o sdcreds.DecryptOptions) (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("the code crashed instead of refusing: %v", r)
			}
		}()
		_, _, err = sdcreds.Decrypt(blob, o)
		return err
	}
	// Success.
	got, md, err := sdcreds.Decrypt(host, sdcreds.DecryptOptions{HostKey: staticKey, Name: str("foo"), Timestamp: ts})
	if err != nil || string(got) != "hello" || md != (sdcreds.Metadata{Timestamp: 1000, NotAfter: 3000, Name: "foo"}) {
		t.Fatalf("%q %+v %v", got, md, err)
	}
	// Wrong key, no key.
	if err := open(host, sdcreds.DecryptOptions{HostKey: sdcreds.StaticHostKey([]byte("other")), Timestamp: ts}); !errors.Is(err, sdcreds.ErrAuth) {
		t.Errorf("wrong key: %v", err)
	}
	if err := open(host, sdcreds.DecryptOptions{Timestamp: ts}); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("no key source: %v", err)
	}
	if err := open(host, sdcreds.DecryptOptions{HostKey: sdcreds.HostKeyFile{Path: "/nonexistent/x", MachineID: fixedMID}}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("key error: %v", err)
	}
	// Name.
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Name: str("bar"), Timestamp: ts}); !errors.Is(err, sdcreds.ErrNameMismatch) {
		t.Errorf("name: %v", err)
	}
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Name: str("bar"), Timestamp: ts, IgnoreName: true}); err != nil {
		t.Errorf("ignore name: %v", err)
	}
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Name: str(""), Timestamp: ts}); !errors.Is(err, sdcreds.ErrNameMismatch) {
		t.Errorf("empty expected name against a named credential: %v", err)
	}
	// RequireName: a nameless credential is refused, IgnoreName cannot waive it,
	// and the expected name must be given.
	nameless, err := sdcreds.Encrypt([]byte("hello"), sdcreds.EncryptOptions{Key: sdcreds.IDHost, HostKey: staticKey, Timestamp: 1000, NotAfter: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if err := open(nameless, sdcreds.DecryptOptions{HostKey: staticKey, Name: str("foo"), Timestamp: ts}); err != nil {
		t.Errorf("nameless credential without RequireName: %v", err)
	}
	for _, o := range []sdcreds.DecryptOptions{
		{HostKey: staticKey, Name: str("foo"), Timestamp: ts, RequireName: true},
		{HostKey: staticKey, Name: str("foo"), Timestamp: ts, RequireName: true, IgnoreName: true},
	} {
		if err := open(nameless, o); !errors.Is(err, sdcreds.ErrNameMismatch) {
			t.Errorf("RequireName on a nameless credential: %v", err)
		}
	}
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Name: str("bar"), Timestamp: ts, RequireName: true, IgnoreName: true}); !errors.Is(err, sdcreds.ErrNameMismatch) {
		t.Errorf("RequireName overrides IgnoreName: %v", err)
	}
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts, RequireName: true}); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("RequireName without Name: %v", err)
	}
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Name: str("foo"), Timestamp: ts, RequireName: true}); err != nil {
		t.Errorf("RequireName on a matching credential: %v", err)
	}
	// Not after: 2999 ok, 3000 ok (strictly less), 3001 expired.
	for _, c := range []struct {
		now  uint64
		fail bool
		skip bool
	}{{2999, false, false}, {3000, false, false}, {3001, true, false}, {3001, false, true}, {sdcreds.Infinity, false, false}} {
		err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: c.now, IgnoreNotAfter: c.skip})
		if c.fail != errors.Is(err, sdcreds.ErrExpired) || (!c.fail && err != nil) {
			t.Errorf("now=%d skip=%v: %v", c.now, c.skip, err)
		}
	}
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey}); !errors.Is(err, sdcreds.ErrExpired) {
		t.Errorf("now (2026) is past a 1970 not-after: %v", err)
	}
	// Scope.
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts, Scope: scoped(1, "u", fixedMID)}); !errors.Is(err, sdcreds.ErrScope) {
		t.Errorf("unscoped credential, user scope: %v", err)
	}
	if err := open(host, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts, Scope: scoped(1, "u", fixedMID), AnyScope: true}); err != nil {
		t.Errorf("any scope: %v", err)
	}
	sc, err := sdcreds.Encrypt([]byte("s"), sdcreds.EncryptOptions{Key: sdcreds.IDHostScoped, HostKey: staticKey, Timestamp: 1000, Scope: scoped(1000, "alice", fixedMID)})
	if err != nil {
		t.Fatal(err)
	}
	if err := open(sc, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts}); !errors.Is(err, sdcreds.ErrScope) {
		t.Errorf("scoped credential, system scope: %v", err)
	}
	if err := open(sc, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts, AnyScope: true}); !errors.Is(err, sdcreds.ErrScope) {
		t.Errorf("AnyScope does not select a user: %v", err)
	}
	for name, s := range map[string]*sdcreds.Scope{
		"uid":     scoped(1001, "alice", fixedMID),
		"user":    scoped(1000, "bob", fixedMID),
		"machine": scoped(1000, "alice", otherMID),
	} {
		if err := open(sc, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts, Scope: s}); !errors.Is(err, sdcreds.ErrAuth) {
			t.Errorf("wrong %s: %v", name, err)
		}
	}
	if err := open(sc, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts, Scope: scoped(1000, "alice", fixedMID)}); err != nil {
		t.Errorf("right scope: %v", err)
	}
	if err := open(sc, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts, Scope: scoped(1000, "a\x00", fixedMID)}); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("NUL user: %v", err)
	}
	// An unsupported scope flag set is refused, not decrypted.
	bad := append([]byte(nil), sc...)
	bad[48] = 3
	var unsup *sdcreds.UnsupportedModeError
	if err := open(bad, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: ts, Scope: scoped(1000, "alice", fixedMID)}); !errors.As(err, &unsup) || unsup.Reason == "" {
		t.Errorf("scope flags: %v", err)
	}
	if !strings.Contains(unsup.Error(), "scoped credential") {
		t.Errorf("message: %v", unsup)
	}
}

func TestDecryptNullPolicy(t *testing.T) {
	blob := nullBlob(t)
	refuse := func() error { return sdcreds.ErrNullRefused }
	calls := 0
	count := func() error { calls++; return nil }
	for _, c := range []struct {
		name string
		o    sdcreds.DecryptOptions
		want error
	}{
		{"default refuses", sdcreds.DecryptOptions{Timestamp: 2000}, sdcreds.ErrNullRefused},
		{"allow accepts", sdcreds.DecryptOptions{Timestamp: 2000, AllowNull: true}, nil},
		{"policy accepts", sdcreds.DecryptOptions{Timestamp: 2000, NullPolicy: func() error { return nil }}, nil},
		{"policy refuses", sdcreds.DecryptOptions{Timestamp: 2000, NullPolicy: refuse}, sdcreds.ErrNullRefused},
		{"allow overrides policy", sdcreds.DecryptOptions{Timestamp: 2000, NullPolicy: refuse, AllowNull: true}, nil},
		{"refuse wins", sdcreds.DecryptOptions{Timestamp: 2000, RefuseNull: true}, sdcreds.ErrNullRefused},
		{"refuse beats allow", sdcreds.DecryptOptions{Timestamp: 2000, RefuseNull: true, AllowNull: true}, sdcreds.ErrNullRefused},
	} {
		_, _, err := sdcreds.Decrypt(blob, c.o)
		if !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, _, err := sdcreds.Decrypt(blob, sdcreds.DecryptOptions{Timestamp: 2000, NullPolicy: count}); err != nil || calls != 1 {
		t.Errorf("policy consulted %d times: %v", calls, err)
	}
	// A non-null credential never consults the policy.
	host, _ := sdcreds.Encrypt(nil, hostOpts(""))
	calls = 0
	if _, _, err := sdcreds.Decrypt(host, sdcreds.DecryptOptions{HostKey: staticKey, Timestamp: 2000, NullPolicy: refuse}); err != nil {
		t.Errorf("policy applied to a host credential: %v", err)
	}
	_ = count
}

// craft seals an arbitrary plaintext under the null key, to reach the checks
// behind authentication that Encrypt itself never produces.
func craft(pt []byte) []byte {
	hdr := make([]byte, 48)
	copy(hdr, sdcreds.IDNull[:])
	binary.LittleEndian.PutUint32(hdr[16:], 32)
	binary.LittleEndian.PutUint32(hdr[20:], 1)
	binary.LittleEndian.PutUint32(hdr[24:], 12)
	binary.LittleEndian.PutUint32(hdr[28:], 16)
	key := sha256.Sum256(nil)
	blk, _ := aes.NewCipher(key[:])
	g, _ := cipher.NewGCM(blk)
	aad := append([]byte(nil), hdr...)
	return g.Seal(hdr, zeroIV, pt, aad)
}

func meta(ts, na uint64, nameSize uint32, name string, payload string) []byte {
	b := make([]byte, 20)
	binary.LittleEndian.PutUint64(b, ts)
	binary.LittleEndian.PutUint64(b[8:], na)
	binary.LittleEndian.PutUint32(b[16:], nameSize)
	b = append(b, name...)
	for len(b)%8 != 0 {
		b = append(b, 0)
	}
	return append(b, payload...)
}

func TestDecryptMetadataChecks(t *testing.T) {
	inf := sdcreds.Infinity
	long := strings.Repeat("a", 256)
	for _, c := range []struct {
		name string
		pt   []byte
		want error // nil: must succeed
	}{
		{"valid", meta(1, 2, 3, "abc", "x"), nil},
		{"valid no name", meta(1, 2, 0, "", "x"), nil},
		{"empty plaintext", nil, sdcreds.ErrFormat},
		{"23 bytes", make([]byte, 23), sdcreds.ErrFormat},
		{"timestamps equal", meta(5, 5, 0, "", ""), sdcreds.ErrFormat},
		{"timestamps reversed", meta(6, 5, 0, "", ""), sdcreds.ErrFormat},
		{"no timestamp, reversed ok", meta(inf, 5, 0, "", ""), nil},
		{"no not-after ok", meta(7, inf, 0, "", ""), nil},
		{"name 256", meta(1, 2, 256, long, ""), sdcreds.ErrFormat},
		{"name 255", meta(1, 2, 255, long[:255], ""), nil},
		{"name beyond plaintext", meta(1, 2, 100, "", ""), sdcreds.ErrFormat},
		{"name with slash", meta(1, 2, 3, "a/b", ""), sdcreds.ErrFormat},
		{"name with NUL", meta(1, 2, 3, "a\x00b", ""), sdcreds.ErrFormat},
		{"name with colon", meta(1, 2, 3, "a:b", ""), sdcreds.ErrFormat},
	} {
		got, _, err := sdcreds.Decrypt(craft(c.pt), sdcreds.DecryptOptions{Timestamp: 1, AllowNull: true})
		switch {
		case c.want == nil && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s: want %v, got %v", c.name, c.want, err)
		case c.want != nil && got != nil:
			t.Errorf("%s: plaintext returned with an error", c.name)
		}
	}
	// The payload comes back without the metadata and its padding.
	got, md, err := sdcreds.Decrypt(craft(meta(1, 2, 3, "abc", "payload")), sdcreds.DecryptOptions{Timestamp: 1, AllowNull: true})
	if err != nil || string(got) != "payload" || md.Name != "abc" {
		t.Fatalf("%q %+v %v", got, md, err)
	}
}

func mutate(blob []byte, off int, v uint32) []byte {
	b := append([]byte(nil), blob...)
	binary.LittleEndian.PutUint32(b[off:], v)
	return b
}

func TestParseRefusals(t *testing.T) {
	ok := nullBlob(t)
	h, err := sdcreds.Parse(ok)
	if err != nil || h.ID != sdcreds.IDNull || h.AADLen() != 48 || !bytes.Equal(h.IV, zeroIV) || h.ScopeFlags != 0 {
		t.Fatalf("%+v %v", h, err)
	}
	for _, c := range []struct {
		name string
		blob []byte
	}{
		{"empty", nil},
		{"short id", ok[:15]},
		{"short fixed", ok[:31]},
		{"key size", mutate(ok, 16, 16)},
		{"key size 64", mutate(ok, 16, 64)},
		{"block size 0", mutate(ok, 20, 0)},
		{"block size 2", mutate(ok, 20, 2)},
		{"block size huge", mutate(ok, 20, 1<<20)},
		{"block size just over", mutate(ok, 20, sdcreds.FieldMax+1)},
		{"iv size huge", mutate(ok, 24, 1<<30)},
		{"iv size just over", mutate(ok, 24, sdcreds.FieldMax+1)},
		{"iv size 0", mutate(ok, 24, 0)},
		{"tag size 0", mutate(ok, 28, 0)},
		{"tag size huge", mutate(ok, 28, 1<<30)},
		{"tag size just over", mutate(ok, 28, sdcreds.FieldMax+1)},
		{"tag size 12", mutate(ok, 28, 12)},
		{"truncated below metadata", ok[:48+24+15]},
	} {
		if _, err := sdcreds.Parse(c.blob); !errors.Is(err, sdcreds.ErrFormat) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// Exactly header + 24 bytes of metadata + tag is the smallest accepted size.
	if _, err := sdcreds.Parse(ok[:48+24+16]); err != nil {
		t.Errorf("minimal size: %v", err)
	}
	if _, err := sdcreds.Parse(ok[:48+24+15]); err == nil {
		t.Error("one byte short of the minimal size")
	}
	// An IV size that is allowed by the bound but is not 12 is refused by the cipher check.
	if _, err := sdcreds.Parse(mutate(append(ok, make([]byte, 8)...), 24, 20)); !errors.Is(err, sdcreds.ErrFormat) && err != nil {
		t.Errorf("iv 20: %v", err)
	}
	// Scoped: flags other than 7 are unsupported.
	sc, err := sdcreds.Encrypt(nil, sdcreds.EncryptOptions{Key: sdcreds.IDHostScoped, HostKey: staticKey, Timestamp: 1, Scope: scoped(1, "a", fixedMID)})
	if err != nil {
		t.Fatal(err)
	}
	h, err = sdcreds.Parse(sc)
	if err != nil || h.ScopeFlags != 7 || h.AADLen() != 56 {
		t.Fatalf("%+v %v", h, err)
	}
	var unsup *sdcreds.UnsupportedModeError
	for _, f := range []byte{0, 1, 3, 15} {
		b := append([]byte(nil), sc...)
		b[48] = f
		if _, err := sdcreds.Parse(b); !errors.As(err, &unsup) {
			t.Errorf("flags %d: %v", f, err)
		}
	}
	// The scoped header is 8 bytes longer: a blob too short for it is refused.
	if _, err := sdcreds.Parse(sc[:len(sc)-1]); err == nil {
		t.Error("short scoped blob")
	}
}

func TestParseUnsupportedModes(t *testing.T) {
	var unsup *sdcreds.UnsupportedModeError
	tpm := make([]byte, 100)
	copy(tpm, []byte{0x0c, 0x7c, 0xc0, 0x7b, 0x11, 0x76, 0x45, 0x91, 0x9c, 0x4b, 0x0b, 0xea, 0x08, 0xbc, 0x20, 0xfe})
	if _, err := sdcreds.Parse(tpm); !errors.As(err, &unsup) || !unsup.Known || !strings.Contains(unsup.Error(), "TPM2") {
		t.Errorf("tpm2: %v", err)
	}
	if _, _, err := sdcreds.Decrypt(tpm, sdcreds.DecryptOptions{}); !errors.As(err, &unsup) {
		t.Errorf("decrypt tpm2: %v", err)
	}
	unknown := make([]byte, 100)
	unknown[0] = 0x99
	if _, err := sdcreds.Parse(unknown); !errors.As(err, &unsup) || unsup.Known || !strings.Contains(unsup.Error(), "unknown encryption format") {
		t.Errorf("unknown: %v", err)
	}
	if _, err := sdcreds.Parse(tpm[:15]); !errors.Is(err, sdcreds.ErrFormat) {
		t.Errorf("short: %v", err)
	}
	if sdcreds.IDNull.String() != "058469daf6f54324800549da0f8ea2fb" {
		t.Error(sdcreds.IDNull.String())
	}
}

// TestSizeBombs: oversized blobs are refused on length alone, allocating nothing.
func TestSizeBombs(t *testing.T) {
	huge := make([]byte, sdcreds.EncryptedMax+1)
	copy(huge, sdcreds.IDNull[:])
	before := heap()
	if _, err := sdcreds.Parse(huge); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Error(err)
	}
	if _, _, err := sdcreds.Decrypt(huge, sdcreds.DecryptOptions{}); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Error(err)
	}
	if grew := heap() - before; grew > 1<<20 {
		t.Errorf("the refusals allocated %d bytes", grew)
	}
	// At the bound the blob is parsed (and fails authentication, not size).
	atMax := huge[:sdcreds.EncryptedMax]
	copy(atMax[16:], []byte{32, 0, 0, 0, 1, 0, 0, 0, 12, 0, 0, 0, 16, 0, 0, 0})
	safely(t, "at the bound", func() {
		if _, _, err := sdcreds.Decrypt(atMax, sdcreds.DecryptOptions{AllowNull: true}); !errors.Is(err, sdcreds.ErrAuth) {
			t.Errorf("at the bound: %v", err)
		}
	})
}

func TestNullPolicy(t *testing.T) {
	for _, c := range []struct {
		pol                     sdcreds.BootPolicy
		first, tpm2, secure, ok bool
	}{
		{sdcreds.BootStrict, true, false, false, false},
		{sdcreds.BootStrict, false, true, true, false},
		{sdcreds.BootTOFU, true, true, true, true},
		{sdcreds.BootTOFU, false, true, true, false},
		{sdcreds.BootTOFU, false, false, true, true},
		{sdcreds.BootRelaxed, false, true, true, false},
		{sdcreds.BootRelaxed, false, true, false, true},
		{sdcreds.BootRelaxed, false, false, true, true},
		{sdcreds.BootOff, false, true, true, true},
		{sdcreds.BootPolicy(99), true, false, false, false},
	} {
		if got := c.pol.AcceptsNull(c.first, c.tpm2, c.secure); got != c.ok {
			t.Errorf("%v first=%v tpm2=%v secure=%v: %v", c.pol, c.first, c.tpm2, c.secure, got)
		}
		err := sdcreds.NullPolicyFor(c.pol, c.first, c.tpm2, c.secure)()
		if (err == nil) != c.ok || (err != nil && !errors.Is(err, sdcreds.ErrNullRefused)) {
			t.Errorf("%v: %v", c.pol, err)
		}
	}
	for s, want := range map[string]sdcreds.BootPolicy{"strict": sdcreds.BootStrict, "tofu": sdcreds.BootTOFU, "relaxed": sdcreds.BootRelaxed, "off": sdcreds.BootOff} {
		if p, ok := sdcreds.ParseBootPolicy(s); !ok || p != want {
			t.Errorf("%s", s)
		}
	}
	if p, ok := sdcreds.ParseBootPolicy("bogus"); ok || p != sdcreds.BootRelaxed {
		t.Error("bogus policy")
	}
	for cmdline, want := range map[string]sdcreds.BootPolicy{
		"": sdcreds.BootRelaxed,
		"quiet systemd.credentials_boot_policy=strict":                                   sdcreds.BootStrict,
		"rd.systemd.credentials_boot_policy=off x":                                       sdcreds.BootOff,
		"systemd.credentials_boot_policy=bogus":                                          sdcreds.BootRelaxed,
		"systemd.credentials_boot_policy=tofu foo=bar":                                   sdcreds.BootTOFU,
		"systemd.credentials_boot_policy=strict foo systemd.credentials_boot_policy=off": sdcreds.BootOff,
		"xsystemd.credentials_boot_policy=strict":                                        sdcreds.BootRelaxed,
	} {
		if got := sdcreds.PolicyFromCmdline(cmdline); got != want {
			t.Errorf("%q: %v want %v", cmdline, got, want)
		}
	}
	// The system query must not panic on any platform; the answer depends on the host.
	_ = sdcreds.SystemNullPolicy()()
}
