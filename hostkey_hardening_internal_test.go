//go:build unix

package sdcreds

import (
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
