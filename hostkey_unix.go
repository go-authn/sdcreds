//go:build unix

package sdcreds

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// readHostSecret returns the whole file (machine id prefix included).
func readHostSecret(path string) ([]byte, error) {
	// O_NOFOLLOW: a symlink as the last component is refused (cu.c:577).
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	switch {
	case st.Mode&syscall.S_IFMT != syscall.S_IFREG:
		return nil, fmt.Errorf("sdcreds: %s is not a regular file", path)
	case st.Nlink == 0:
		return nil, fmt.Errorf("sdcreds: %s was deleted", path)
	case st.Nlink > 1:
		return nil, fmt.Errorf("sdcreds: %s has too many links, refusing", path)
	case st.Mode&07777 != 0400:
		return nil, fmt.Errorf("sdcreds: %s has permissive access mode, refusing (want 0400)", path)
	case st.Size < 16+1:
		return nil, fmt.Errorf("sdcreds: %s is too small, refusing", path)
	case st.Size > HostSecretMax:
		return nil, fmt.Errorf("sdcreds: %s is too big, refusing: %w", path, ErrTooLarge)
	}
	buf := make([]byte, st.Size+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, &os.PathError{Op: "read", Path: path, Err: err}
	}
	if int64(n) != st.Size { // the size changed under us (cu.c:629)
		return nil, fmt.Errorf("sdcreds: failed to read %s: size changed", path)
	}
	return buf[:n], nil
}

func createHostSecret(path string, machineID [16]byte) ([]byte, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	tmp, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf(".sdcreds-%d.tmp", os.Getpid())), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	prefix := HostSecretMachineID(machineID)
	data := make([]byte, HostSecretDataSize)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	if _, err := tmp.Write(append(append([]byte{}, prefix[:]...), data...)); err != nil {
		return nil, err
	}
	if err := tmp.Chmod(0o400); err != nil {
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		return nil, err
	}
	// link(2) refuses to replace an existing file, like link_tmpfile_at.
	if err := os.Link(tmp.Name(), path); err != nil {
		return nil, err
	}
	return data, nil
}
