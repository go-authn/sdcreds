//go:build unix

package sdcreds

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// HostKeyFromFile judges and reads the descriptor it is given: the checks of
// HostKey, a null machine id refused, and no path opened (the path is replaced
// after the open, and the bytes of the opened file are still the ones returned).
func TestHostKeyFromFile(t *testing.T) {
	defer crashed(t)
	mid := [16]byte{7}
	prefix := HostSecretMachineID(mid)
	body := append(append([]byte{}, prefix[:]...), 1, 2, 3)
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, body, 0o400); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := HostKeyFromFile(f, [16]byte{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("null machine id: %v", err)
	}
	if _, err := HostKeyFromFile(f, [16]byte{8}); !errors.Is(err, ErrHostKeyMachine) {
		t.Errorf("other machine: %v", err)
	}
	// a file the checks refuse is an error, and no key.
	loose := filepath.Join(filepath.Dir(p), "loose")
	if err := os.WriteFile(loose, body, 0o444); err != nil {
		t.Fatal(err)
	}
	lf, err := os.Open(loose)
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	if k, err := HostKeyFromFile(lf, mid); err == nil || k != nil || !strings.Contains(err.Error(), "access mode") {
		t.Errorf("loose file: %x %v", k, err)
	}
	if err := os.Rename(p, p+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, bytes.Repeat([]byte{9}, 40), 0o400); err != nil {
		t.Fatal(err)
	}
	k, err := HostKeyFromFile(f, mid)
	if err != nil || !bytes.Equal(k, []byte{1, 2, 3}) {
		t.Errorf("%x %v", k, err)
	}
}

// HostKeyFromFileMode wants the mode it is given and no other: the OpenBSD
// host key is 0600, and neither 0400 nor a looser mode passes for it.
func TestHostKeyFromFileMode(t *testing.T) {
	defer crashed(t)
	mid := [16]byte{7}
	prefix := HostSecretMachineID(mid)
	body := append(append([]byte{}, prefix[:]...), 1, 2, 3)
	for _, c := range []struct {
		mode os.FileMode
		ok   bool
	}{{0o600, true}, {0o400, false}, {0o640, false}, {0o660, false}, {0o700, false}} {
		p := filepath.Join(t.TempDir(), "k")
		if err := os.WriteFile(p, body, c.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, c.mode); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		k, err := HostKeyFromFileMode(f, mid, 0o600)
		f.Close()
		switch {
		case c.ok && (err != nil || !bytes.Equal(k, []byte{1, 2, 3})):
			t.Errorf("mode %v: %x %v", c.mode, k, err)
		case !c.ok && (err == nil || k != nil || !strings.Contains(err.Error(), "access mode")):
			t.Errorf("mode %v accepted: %x %v", c.mode, k, err)
		}
	}
	if _, err := HostKeyFromFileMode(nil, [16]byte{}, 0o600); !errors.Is(err, ErrInvalid) {
		t.Errorf("null machine id: %v", err)
	}
}
