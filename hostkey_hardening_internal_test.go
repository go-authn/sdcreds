//go:build unix

package sdcreds

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A FIFO where the host secret should be is refused at once: opening it must
// not wait for a writer.
func TestHostSecretFIFOIsRefusedNotAwaited(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := syscall.Mkfifo(p, 0o400); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := readHostSecret(p); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Errorf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reading a FIFO as the host secret blocks")
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return len(b) > 0
}

// spyKey records the host key it hands out; being a HostKeyFile inside, it is
// ephemeral too.
type spyKey struct {
	HostKeyFile
	got *[]byte
}

func (s spyKey) HostKey() ([]byte, error) {
	k, err := s.HostKeyFile.HostKey()
	*s.got = k
	return k, err
}

// The host secret read from a file is overwritten once it has been hashed into
// the credential key; a static key belongs to the caller and is left alone.
func TestHostSecretIsWipedOnEveryPath(t *testing.T) {
	mid := [16]byte{7}
	p := filepath.Join(t.TempDir(), "secret")
	prefix := HostSecretMachineID(mid)
	data := bytes.Repeat([]byte{0xAA}, 64)
	if err := os.WriteFile(p, append(prefix[:], data...), 0o400); err != nil {
		t.Fatal(err)
	}
	var got []byte
	key := spyKey{HostKeyFile{Path: p, MachineID: mid}, &got}
	blob, err := Encrypt([]byte("x"), EncryptOptions{Key: IDHost, HostKey: key, Name: "n"})
	if err != nil {
		t.Fatal(err)
	}
	if !allZero(got) {
		t.Errorf("encrypt left the host secret in memory: %x", got[:8])
	}
	if _, _, err := Decrypt(blob, DecryptOptions{HostKey: key, Name: ptr("n")}); err != nil {
		t.Fatal(err)
	}
	if !allZero(got) {
		t.Errorf("decrypt left the host secret in memory: %x", got[:8])
	}
	// A static key is the caller's: untouched.
	st := bytes.Repeat([]byte{0xBB}, 32)
	if _, err := Encrypt([]byte("x"), EncryptOptions{Key: IDHost, HostKey: StaticHostKey(st)}); err != nil {
		t.Fatal(err)
	}
	if st[0] != 0xBB {
		t.Error("a static key was overwritten")
	}

	// The buffer is wiped when the machine id does not match, and when the
	// read fails or the size changed.
	defer func(r func(io.Reader, []byte) (int, error)) { readFull = r }(readFull)
	var buf []byte
	readFull = func(r io.Reader, b []byte) (int, error) {
		buf = b
		return io.ReadFull(r, b)
	}
	if _, err := (HostKeyFile{Path: p, MachineID: [16]byte{9}}).HostKey(); !errors.Is(err, ErrHostKeyMachine) {
		t.Fatalf("%v", err)
	}
	if !allZero(buf) {
		t.Error("mismatched secret left in memory")
	}
	for name, c := range map[string]struct {
		n   int
		err error
	}{"io error": {0, io.ErrClosedPipe}, "size changed": {10, io.ErrUnexpectedEOF}} {
		readFull = func(r io.Reader, b []byte) (int, error) {
			buf = b
			for i := range b {
				b[i] = 0xCC
			}
			return c.n, c.err
		}
		if _, err := readHostSecret(p); err == nil {
			t.Fatalf("%s accepted", name)
		}
		if !allZero(buf) {
			t.Errorf("%s: the partial read stayed in memory", name)
		}
	}
}

func ptr(s string) *string { return &s }

func TestOwnerTrusted(t *testing.T) {
	for _, c := range []struct {
		uid  uint32
		euid int
		want bool
	}{{0, 0, true}, {0, 1000, true}, {1000, 1000, true}, {1001, 1000, false}, {1000, 0, false}, {1, 0, false}} {
		if got := ownerTrusted(c.uid, c.euid); got != c.want {
			t.Errorf("owner %d, euid %d: %v", c.uid, c.euid, got)
		}
	}
}

// A secret owned by someone who is neither root nor the caller is refused.
func TestHostSecretOfAnotherUserIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root-owned file is trusted whoever asks")
	}
	p := secretFile(t, 64)
	defer func(o func() int) { geteuid = o }(geteuid)
	geteuid = func() int { return os.Getuid() + 1 }
	if _, err := readHostSecret(p); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Errorf("%v", err)
	}
	geteuid = os.Geteuid
	if _, err := readHostSecret(p); err != nil {
		t.Errorf("own file: %v", err)
	}
}
