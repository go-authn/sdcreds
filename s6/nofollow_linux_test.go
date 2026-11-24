//go:build linux

package s6

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// pin never follows a symbolic link, and unmount never follows one to the
// mount behind it: swapping a directory for a link cannot redirect either.
func TestSymlinkIsNeverFollowedByPinOrUnmount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	// The mount lives in a namespace of its own, which dies with this thread.
	runtime.LockOSThread()
	if err := unshare(); err != nil {
		t.Skip(err)
	}
	root := t.TempDir()
	real, link := filepath.Join(root, "real"), filepath.Join(root, "link")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, release, err := pin(link); err == nil {
		release()
		t.Error("pin followed a symbolic link")
	}
	if _, release, err := pin(real); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	if err := mountRAM(real); err != nil {
		t.Skip(err)
	}
	if err := unmount(link); !errors.Is(err, ErrNotMounted) {
		t.Errorf("unmount through a link: %v", err)
	}
	if typ, err := fsType(real); err != nil || typ != "tmpfs" && typ != "ramfs" {
		t.Errorf("the mount behind the link was detached: %q %v", typ, err)
	}
	if err := unmount(real); err != nil {
		t.Error(err)
	}
}
