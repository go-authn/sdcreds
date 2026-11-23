//go:build unix

package s6

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A directory that cannot be opened is reported with the reason of the open,
// not with the error of a mode change on a descriptor that does not exist.
func TestFchmodDirReportsTheOpenError(t *testing.T) {
	dir := t.TempDir()
	if err := fchmodDir(filepath.Join(dir, "absent"), 0o755); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing directory: %v", err)
	}
	if err := os.Symlink(dir, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	err := fchmodDir(filepath.Join(dir, "link"), 0o755)
	if !errors.Is(err, syscall.ELOOP) && !errors.Is(err, syscall.ENOTDIR) {
		t.Errorf("symbolic link followed or misreported: %v", err)
	}
	if err := fchmodDir(dir, 0o700); err != nil {
		t.Errorf("directory: %v", err)
	}
}
