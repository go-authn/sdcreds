//go:build unix

package sdcreds

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secretFile writes a 0400 file of size bytes and returns its path.
func secretFile(t *testing.T, size int) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, bytes.Repeat([]byte{1}, size), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}

// crashed turns a panic into a failed assertion, so that a deleted guard is
// reported by the test that asserts what the guard is for.
func crashed(t *testing.T) {
	t.Helper()
	if r := recover(); r != nil {
		t.Errorf("the code crashed instead of refusing: %v", r)
	}
}

func TestReadHostSecretKernelFailures(t *testing.T) {
	defer crashed(t)
	p := secretFile(t, 64)
	// a missing file is an error of HostKey, not a short secret.
	if k, err := (HostKeyFile{Path: p + ".none", MachineID: [16]byte{1}}).HostKey(); err == nil || k != nil {
		t.Errorf("missing file: %x %v", k, err)
	}
	defer func(o func(string) (*os.File, error), r func(io.Reader, []byte) (int, error)) {
		openSecret, readFull = o, r
	}(openSecret, readFull)

	// fstat fails on a closed file.
	openSecret = func(path string) (*os.File, error) {
		f, err := os.Open(path)
		if err == nil {
			f.Close()
		}
		return f, err
	}
	if _, err := readHostSecret(p); err == nil {
		t.Error("fstat failure was not reported")
	}

	// the file is unlinked while open: no links left.
	openSecret = func(path string) (*os.File, error) {
		f, err := os.Open(path)
		if err == nil {
			err = os.Remove(path)
		}
		return f, err
	}
	if _, err := readHostSecret(p); err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Errorf("unlinked file: %v", err)
	}

	// read errors, and a size that changed between fstat and read.
	p = secretFile(t, 64)
	openSecret = func(path string) (*os.File, error) { return os.Open(path) }
	for name, c := range map[string]struct {
		n    int
		err  error
		want string
	}{
		"io error":      {0, io.ErrClosedPipe, "read"},
		"io error late": {64, io.ErrClosedPipe, "read"},
		"shrunk":        {63, io.ErrUnexpectedEOF, "size changed"},
		"grown":         {65, nil, "size changed"},
		"grown, eof":    {65, io.ErrUnexpectedEOF, "size changed"},
	} {
		readFull = func(io.Reader, []byte) (int, error) { return c.n, c.err }
		if _, err := readHostSecret(p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the normal short read of a file of exactly the expected size.
	readFull = func(r io.Reader, b []byte) (int, error) { return len(b) - 1, io.ErrUnexpectedEOF }
	if b, err := readHostSecret(p); err != nil || len(b) != 64 {
		t.Errorf("exact size: %d %v", len(b), err)
	}
}

func TestCreateHostSecretFailures(t *testing.T) {
	defer crashed(t)
	mid := [16]byte{1}
	dir := t.TempDir()

	// the directory cannot be created: a regular file is in the way.
	if err := os.WriteFile(filepath.Join(dir, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := createHostSecret(filepath.Join(dir, "file", "sub", "secret"), mid); err == nil {
		t.Error("no directory")
	}

	// the final path exists: link(2) refuses to replace it and nothing is left.
	exist := filepath.Join(dir, "exist")
	if err := os.WriteFile(exist, []byte("keep"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := createHostSecret(exist, mid); err == nil {
		t.Error("an existing secret was replaced")
	}
	if b, _ := os.ReadFile(exist); string(b) != "keep" {
		t.Errorf("existing secret modified: %q", b)
	}

	// fsync fails: no secret, no temporary file.
	defer func(o func(*os.File) error) { syncFile = o }(syncFile)
	syncFile = func(*os.File) error { return errors.New("injected") }
	p := filepath.Join(dir, "new", "secret")
	if _, err := createHostSecret(p, mid); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Errorf("sync failure: %v", err)
	}
	if _, err := os.Lstat(p); err == nil {
		t.Error("a secret was published after a failed sync")
	}
	if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 0 {
		t.Errorf("temporary file left behind: %v", ents)
	}
}

func TestMachineIDMissing(t *testing.T) {
	defer crashed(t)
	defer func(o string) { machineIDFile = o }(machineIDFile)
	machineIDFile = filepath.Join(t.TempDir(), "none")
	if _, err := ReadMachineID(""); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%v", err)
	}
	// Both consumers of the default report it instead of using a zero id.
	p := secretFile(t, 64)
	if _, err := (HostKeyFile{Path: p}).HostKey(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("host key: %v", err)
	}
	_, err := Encrypt(nil, EncryptOptions{Key: IDHostScoped, HostKey: StaticHostKey([]byte("k")), Timestamp: 1, Scope: &Scope{UID: 1, Username: "a"}})
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("scope: %v", err)
	}
}
