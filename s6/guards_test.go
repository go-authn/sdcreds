package s6

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds"
)

// safely turns a panic into an error, so that a guard that is missing is an
// assertion failure naming what it should have said, not a crash.
func safely(f func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return f()
}

func acceptAll(string, []byte) ([]byte, error) { return []byte("x"), nil }

func TestNoCommandIsNamed(t *testing.T) {
	r, c := newRig(t), config(t)
	c.Command = nil
	err := safely(func() error { return Run(c, r.ops()) })
	if err == nil || !strings.Contains(err.Error(), "no command") {
		t.Errorf("%v", err)
	}
}

// With a decryption that accepts anything, only the guards of the source
// directory can refuse these entries.
func TestSourceEntriesAreRefusedByTheirOwnGuards(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links")
	}
	for name, c := range map[string]struct {
		mk   func(src string)
		want string
	}{
		"bad name": {func(src string) { os.WriteFile(filepath.Join(src, "a:b"), []byte("x"), 0o600) }, "not a valid credential name"},
		"symlink":  {func(src string) { os.Symlink(filepath.Join(src, "token"), filepath.Join(src, "link")) }, "not a regular file"},
		"missing":  {func(src string) { os.Symlink(filepath.Join(src, "none"), filepath.Join(src, "dangling")) }, "not a regular file"},
	} {
		r, cfg := newRig(t), config(t)
		cfg.Decrypt = acceptAll
		c.mk(cfg.Source)
		err := safely(func() error { return Run(cfg, r.ops()) })
		if err == nil || !strings.Contains(err.Error(), c.want) || slices.Contains(r.calls, "mount") {
			t.Errorf("%s: %v %v", name, err, r.calls)
		}
	}
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

func TestReadBounded(t *testing.T) {
	boom := errors.New("disk on fire")
	if _, err := readBounded(failingReader{boom}); !errors.Is(err, boom) || errors.Is(err, sdcreds.ErrTooLarge) {
		t.Errorf("read error: %v", err)
	}
	if b, err := readBounded(bytes.NewReader(make([]byte, maxArmoured))); err != nil || len(b) != maxArmoured {
		t.Errorf("at the bound: %d %v", len(b), err)
	}
	if _, err := readBounded(bytes.NewReader(make([]byte, maxArmoured+1))); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Errorf("over the bound: %v", err)
	}
}

func TestReadLimitedFiles(t *testing.T) {
	dir := t.TempDir()
	err := safely(func() error { _, err := readLimited(filepath.Join(dir, "none")); return err })
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return
	}
	p := filepath.Join(dir, "locked")
	os.WriteFile(p, []byte("x"), 0o000)
	err = safely(func() error { _, err := readLimited(p); return err })
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("unreadable file: %v", err)
	}
}

// refused runs Run with the given ops and reports whether it failed before
// any file was handed to the service.
func refused(t *testing.T, r *rig, c Config, o Ops) error {
	t.Helper()
	err := safely(func() error { return Run(c, o) })
	if err == nil || errors.Is(err, errExec) || slices.Contains(r.calls, "exec") || slices.Contains(r.calls, "drop") {
		t.Errorf("not refused: %v %v", err, r.calls)
	}
	return err
}

func TestSetupFailuresAreNotIgnored(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links and modes")
	}
	t.Run("base directory below a file", func(t *testing.T) {
		r, c := newRig(t), config(t)
		file := filepath.Join(t.TempDir(), "file")
		os.WriteFile(file, nil, 0o600)
		c.BaseDir = filepath.Join(file, "x")
		refused(t, r, c, r.ops())
		if slices.Contains(r.calls, "mount") {
			t.Errorf("mounted: %v", r.calls)
		}
	})
	t.Run("directory gone after the mount", func(t *testing.T) {
		r, c := newRig(t), config(t)
		o := r.ops()
		o.MountRAM = func(dir string) error { r.calls = append(r.calls, "mount"); return os.Remove(dir) }
		err := refused(t, r, c, o)
		if !strings.Contains(err.Error(), "chmod") || slices.Contains(r.calls, "chown") || !slices.Contains(r.calls, "unmount") {
			t.Errorf("%v %v", err, r.calls)
		}
	})
	t.Run("a planted file is not followed", func(t *testing.T) {
		r, c := newRig(t), config(t)
		target := filepath.Join(t.TempDir(), "target")
		os.WriteFile(target, []byte("untouched"), 0o600)
		o := r.ops()
		o.MountRAM = func(dir string) error {
			r.calls = append(r.calls, "mount")
			return os.Symlink(target, filepath.Join(dir, "token"))
		}
		refused(t, r, c, o)
		if b, _ := os.ReadFile(target); string(b) != "untouched" {
			t.Errorf("the planted link was written through: %q", b)
		}
	})
	t.Run("chown of one credential", func(t *testing.T) {
		for _, name := range []string{"db-password", "token"} {
			r, c := newRig(t), config(t)
			r.failChown[name] = errors.New("no such owner")
			err := refused(t, r, c, r.ops())
			if !strings.Contains(err.Error(), "no such owner") {
				t.Errorf("%s: %v", name, err)
			}
		}
	})
	t.Run("chown of the directory", func(t *testing.T) {
		r, c := newRig(t), config(t)
		r.failChown["web"] = errors.New("no such owner")
		err := refused(t, r, c, r.ops())
		if !strings.Contains(err.Error(), "no such owner") || slices.Contains(r.calls, "remount") {
			t.Errorf("%v %v", err, r.calls)
		}
	})
}

type badFile struct{ werr, cerr error }

func (b badFile) Write(p []byte) (int, error) {
	if b.werr != nil {
		return 0, b.werr
	}
	return len(p), nil
}
func (b badFile) Close() error { return b.cerr }

func TestWriteAndCloseFailuresAreNotIgnored(t *testing.T) {
	defer func(o func(string) (io.WriteCloser, error)) { create = o }(create)
	for name, f := range map[string]badFile{
		"write":           {werr: errors.New("disk full")},
		"close":           {cerr: errors.New("close failed")},
		"write and close": {werr: errors.New("disk full"), cerr: errors.New("close failed")},
	} {
		create = func(string) (io.WriteCloser, error) { return f, nil }
		r, c := newRig(t), config(t)
		err := refused(t, r, c, r.ops())
		for _, e := range []error{f.werr, f.cerr} {
			if e != nil && !errors.Is(err, e) {
				t.Errorf("%s: %v lacks %v", name, err, e)
			}
		}
		if slices.Contains(r.calls, "chown") {
			t.Errorf("%s: chown after a failed write", name)
		}
	}
	create = func(string) (io.WriteCloser, error) { return nil, errors.New("cannot create") }
	r, c := newRig(t), config(t)
	if err := refused(t, r, c, r.ops()); !strings.Contains(err.Error(), "cannot create") {
		t.Errorf("%v", err)
	}
}
