package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/internal/vecspec"
)

// The generator is tested against a stand-in for systemd-creds: this test
// binary, started again with GENVECTORS_FAKE=1, that implements the
// command lines the generator uses with the library and prints systemd's
// messages. GENVECTORS_FAKE_MODE makes it fail in one chosen way.
func TestMain(m *testing.M) {
	if os.Getenv("GENVECTORS_FAKE") == "1" {
		os.Exit(fakeSystemdCreds(os.Args[1:], os.Stdout, os.Stderr))
	}
	if runtime.GOOS == "windows" {
		// The generator writes a host secret file, which only unix systems have.
		fmt.Println("genvectors: tests skipped, a host secret file needs a unix system")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeSystemdCreds(args []string, stdout, stderr io.Writer) int {
	mode := os.Getenv("GENVECTORS_FAKE_MODE")
	secret := os.Getenv("SYSTEMD_CREDENTIAL_SECRET")
	mid, _ := sdcreds.ParseMachineID([]byte(vecspec.MachineID))
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, format+"\n", a...)
		return 1
	}
	if len(args) == 0 {
		return fail("no command")
	}
	cmd, args := args[0], args[1:]
	var with, name string
	var ts, na, uid int64 = 0, 0, -1
	var files []string
	nameSet := false
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--with-key="):
			with = strings.TrimPrefix(a, "--with-key=")
		case strings.HasPrefix(a, "--timestamp=@"):
			ts, _ = strconv.ParseInt(strings.TrimPrefix(a, "--timestamp=@"), 10, 64)
		case strings.HasPrefix(a, "--not-after=@"):
			na, _ = strconv.ParseInt(strings.TrimPrefix(a, "--not-after=@"), 10, 64)
		case strings.HasPrefix(a, "--name="):
			name, nameSet = strings.TrimPrefix(a, "--name="), true
		case strings.HasPrefix(a, "--uid="):
			uid, _ = strconv.ParseInt(strings.TrimPrefix(a, "--uid="), 10, 64)
		case a == "--allow-null":
		default:
			files = append(files, a)
		}
	}
	scope := func() *sdcreds.Scope {
		if uid < 0 {
			return nil
		}
		return &sdcreds.Scope{UID: uint32(uid), Username: vecspec.User, MachineID: mid}
	}
	hk := sdcreds.HostKeyFile{Path: secret, MachineID: mid}
	switch cmd {
	case "setup":
		switch mode {
		case "setup-fails":
			return fail("setup refused")
		case "setup-noop":
			return 0
		case "setup-badprefix":
			if err := os.WriteFile(secret, bytes.Repeat([]byte{1}, 40), 0o400); err != nil {
				return fail("%v", err)
			}
			return 0
		}
		if _, err := sdcreds.CreateHostKey(secret, mid); err != nil {
			return fail("%v", err)
		}
	case "encrypt":
		if mode == "encrypt-fails" {
			return fail("encrypt refused")
		}
		if mode == "encrypt-skip-base" && filepath.Base(files[1]) == "host.name-foo.na-inf.one.cred" {
			return 0
		}
		plain, err := os.ReadFile(files[0])
		if err != nil {
			return fail("%v", err)
		}
		o := sdcreds.EncryptOptions{Key: sdcreds.IDHost, HostKey: hk, Name: name, Timestamp: uint64(ts) * 1_000_000, NotAfter: uint64(na) * 1_000_000}
		switch with {
		case "null":
			o.Key = sdcreds.IDNull
		case "host":
			if uid >= 0 {
				o.Key, o.Scope = sdcreds.IDHostScoped, scope()
			}
		}
		blob, err := sdcreds.Encrypt(plain, o)
		if err != nil {
			return fail("%v", err)
		}
		if err := os.WriteFile(files[1], []byte(sdcreds.Armor(blob, sdcreds.ArmorWidth)), 0o644); err != nil {
			return fail("%v", err)
		}
	case "decrypt":
		if mode == "decrypt-weird" || (mode == "decrypt-weird-tampered" && strings.Contains(files[0], "flip-")) {
			return fail("something nobody expected")
		}
		text, err := os.ReadFile(files[0])
		if err != nil {
			return fail("Failed to read encrypted credential: %v", err)
		}
		blob, err := sdcreds.Unarmor(text)
		if err != nil {
			return fail("Unexpected end of input")
		}
		o := sdcreds.DecryptOptions{HostKey: hk, Timestamp: uint64(ts) * 1_000_000, Scope: scope(), AllowNull: true}
		if nameSet && name != "" {
			o.Name = &name
		}
		pt, _, err := sdcreds.Decrypt(blob, o)
		switch {
		case err == nil:
			if mode == "decrypt-wrongpayload" {
				pt = append(pt, 0)
			}
			stdout.Write(pt)
			return 0
		case errors.Is(err, sdcreds.ErrNameMismatch):
			return fail("Embedded credential name does not match filename, refusing.")
		case errors.Is(err, sdcreds.ErrExpired):
			return fail("Credential's time passed, refusing.")
		case errors.Is(err, sdcreds.ErrScope):
			return fail("Encrypted file is scoped to a user")
		case errors.Is(err, sdcreds.ErrAuth):
			return fail("Decryption failed")
		}
		return fail("Encrypted file too short.")
	default:
		return fail("unknown command %q", cmd)
	}
	return 0
}

func fake(t *testing.T, mode string) func(args ...string) *exec.Cmd {
	t.Helper()
	t.Setenv("GENVECTORS_FAKE", "1")
	t.Setenv("GENVECTORS_FAKE_MODE", mode)
	// Under -race the runtime sleeps atexit_sleep_ms (1000 by default) before a
	// process exits. The generator starts the stand-in about 540 times per run,
	// so that is 350 s per test instead of 0.4 s (measured: setup 1.013 s, the
	// same encrypt 0.007 s with atexit_sleep_ms=0). The sleep only lets a
	// running race report flush; the stand-in is a child whose reports the test
	// does not read. The stand-in still runs with the race detector on; CI also
	// runs the whole matrix without -race.
	race := "atexit_sleep_ms=0"
	if old := os.Getenv("GORACE"); old != "" {
		race = old + " " + race
	}
	t.Setenv("GORACE", race)
	return func(args ...string) *exec.Cmd { return exec.Command(os.Args[0], args...) }
}

// runFake runs the generator against the stand-in; a panic is an error, so
// that a deleted guard fails the assertion about what the guard refuses.
func runFake(t *testing.T, mode string) (dir string, err error) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "vectors")
	cmd := fake(t, mode)
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("the generator crashed instead of refusing: %v", r)
		}
	}()
	return dir, run(dir, filepath.Join(root, "machine-id"), cmd)
}

func TestRunWritesTheMatrixAndTheManifest(t *testing.T) {
	root := t.TempDir()
	dir, id := filepath.Join(root, "vectors"), filepath.Join(root, "machine-id")
	if err := run(dir, id, fake(t, "")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(id); string(b) != vecspec.MachineID+"\n" {
		t.Errorf("machine id file: %q", b)
	}
	m, err := vecspec.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if m.Systemd != "262.2" || m.MachineID != vecspec.MachineID || m.UID != vecspec.UID || m.Timestamp != vecspec.Timestamp {
		t.Errorf("%+v", m)
	}
	if want := len(vecspec.Matrix()) + 5; len(m.Vectors) != want {
		t.Fatalf("%d vectors, want %d", len(m.Vectors), want)
	}
	tampered := map[string]vecspec.Class{}
	for _, v := range m.Vectors {
		if _, err := os.Stat(filepath.Join(dir, v.File)); err != nil {
			t.Errorf("%s: %v", v.File, err)
		}
		if len(v.Decrypt) == 0 {
			t.Errorf("%s: no decryption recorded", v.File)
		}
		if v.Tamper != "" {
			tampered[v.Tamper] = v.Decrypt[0].Expect
		}
	}
	if tampered["flip-iv"] != vecspec.Auth || tampered["flip-ciphertext"] != vecspec.Auth || tampered["flip-tag"] != vecspec.Auth ||
		tampered["truncate-tag"] != vecspec.Auth || tampered["truncate-header"] != vecspec.Format || len(tampered) != 5 {
		t.Errorf("%v", tampered)
	}
	// A host.name-foo vector decrypts with its name and fails with another.
	for _, v := range m.Vectors {
		if v.File != "host.name-foo.na-inf.one.cred" {
			continue
		}
		got := map[string]vecspec.Class{}
		for _, d := range v.Decrypt {
			if d.Now == vecspec.NowEarly && !d.Scoped {
				k := "<none>"
				if d.Name != nil {
					k = *d.Name
				}
				got[k] = d.Expect
			}
		}
		if got["foo"] != vecspec.OK || got["bar"] != vecspec.NameMismatch || got["<none>"] != vecspec.OK {
			t.Errorf("%v", got)
		}
	}
	// With the secret in place a second run does not call setup again.
	t.Setenv("GENVECTORS_FAKE_MODE", "setup-fails")
	if err := run(dir, filepath.Join(root, "machine-id-2"), func(args ...string) *exec.Cmd { return exec.Command(os.Args[0], args...) }); err != nil {
		t.Errorf("second run: %v", err)
	}
}

func TestRunRefusals(t *testing.T) {
	for _, c := range []struct {
		mode, want string
	}{
		{"setup-fails", "setup"},
		{"setup-noop", "no such file"},
		{"setup-badprefix", "prefix"},
		{"encrypt-fails", "systemd-creds"},
		{"decrypt-weird", "unclassified"},
		{"decrypt-wrongpayload", "payload differs"},
		{"encrypt-skip-base", "genvectors"},
		{"decrypt-weird-tampered", "unclassified"},
	} {
		_, err := runFake(t, c.mode)
		if err == nil || !strings.Contains(err.Error(), c.want) && c.mode != "encrypt-skip-base" {
			t.Errorf("%s: %v", c.mode, err)
		}
		if c.mode == "encrypt-skip-base" && (err == nil || !errors.Is(err, os.ErrNotExist)) {
			t.Errorf("%s: %v", c.mode, err)
		}
	}
}

func TestRunSetupErrors(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	os.WriteFile(file, nil, 0o600)
	cmd := fake(t, "")
	if err := run(filepath.Join(file, "sub"), filepath.Join(root, "id"), cmd); err == nil || !strings.Contains(err.Error(), "mkdir") {
		t.Errorf("directory under a file: %v", err)
	}
	if err := run(filepath.Join(root, "v"), filepath.Join(root, "no", "such", "id"), cmd); err == nil {
		t.Error("machine id in a missing directory")
	}
	defer func(o func(string) (string, error)) { absPath = o }(absPath)
	absPath = func(string) (string, error) { return "", errors.New("injected") }
	if err := run(filepath.Join(root, "v2"), filepath.Join(root, "id2"), cmd); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Errorf("abs: %v", err)
	}
	absPath = filepath.Abs
	defer func(o string) { machineID = o }(machineID)
	machineID = "not a machine id"
	if err := run(filepath.Join(root, "v3"), filepath.Join(root, "id3"), cmd); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("bad machine id: %v", err)
	}
	machineID = vecspec.MachineID
	t.Setenv("TMPDIR", filepath.Join(root, "missing-tmp"))
	if err := run(filepath.Join(root, "v4"), filepath.Join(root, "id4"), cmd); err == nil || !strings.Contains(err.Error(), "missing-tmp") {
		t.Errorf("missing temporary directory: %v", err)
	}
	t.Setenv("TMPDIR", root)
	defer func(o func(string, []byte, os.FileMode) error) { writeSecret = o }(writeSecret)
	writeSecret = func(string, []byte, os.FileMode) error { return errors.New("no private copy") }
	if err := run(filepath.Join(root, "v5"), filepath.Join(root, "id5"), cmd); err == nil || !strings.Contains(err.Error(), "no private copy") {
		t.Errorf("private copy of the secret: %v", err)
	}
}

func TestEncryptRefusals(t *testing.T) {
	c := creds{secret: filepath.Join(t.TempDir(), "s"), command: fake(t, "")}
	v := &vecspec.Vector{File: "x.cred", Mode: "null", Payload: "one"}
	if err := encrypt(c, filepath.Join(t.TempDir(), "missing"), t.TempDir(), v); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing temporary directory: %v", err)
	}
	if err := encrypt(c, t.TempDir(), t.TempDir(), v); err != nil {
		t.Errorf("%v", err)
	}
}
