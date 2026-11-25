//go:build unix

package delivery

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/go-authn/sdcreds"
)

func TestReadSourceRefusals(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// exactly MaxEntries entries are read; one more is refused before any is opened.
	for i := 0; i < MaxEntries; i++ {
		write("c"+strconv.Itoa(i), 1)
	}
	if got, err := ReadSource(dir); err != nil || len(got) != MaxEntries {
		t.Fatalf("MaxEntries entries: %d, %v", len(got), err)
	}
	write("one-more", 1)
	if _, err := ReadSource(dir); !errors.Is(err, ErrTooManyEntry) {
		t.Fatalf("MaxEntries+1 entries: %v", err)
	}
	// the count is judged before any file is opened: a link among them does not change the answer.
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "a-link")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadSource(dir); !errors.Is(err, ErrTooManyEntry) {
		t.Fatalf("count before opening: %v", err)
	}
}

func TestReadSourceEachRefusal(t *testing.T) {
	boom := errors.New("boom")
	mk := func(t *testing.T) (string, func(string, int)) {
		dir := t.TempDir()
		return dir, func(name string, n int) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(dir, name), make([]byte, n), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("bad name", func(t *testing.T) {
		dir, write := mk(t)
		write("a:b", 1)
		if _, err := ReadSource(dir); !errors.Is(err, ErrBadName) {
			t.Fatal(err)
		}
	})
	t.Run("missing directory", func(t *testing.T) {
		if _, err := ReadSource(filepath.Join(t.TempDir(), "none")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
	})
	t.Run("symbolic link says so", func(t *testing.T) {
		dir, _ := mk(t)
		if err := os.Symlink("/etc/passwd", filepath.Join(dir, "l")); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSource(dir); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatal(err)
		}
	})
	t.Run("unreadable file is an open error", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root reads everything")
		}
		dir, write := mk(t)
		write("closed", 1)
		if err := os.Chmod(filepath.Join(dir, "closed"), 0); err != nil {
			t.Fatal(err)
		}
		var pe *os.PathError
		if _, err := ReadSource(dir); !errors.Is(err, fs.ErrPermission) || !errors.As(err, &pe) || pe.Op != "open" {
			t.Fatal(err)
		}
	})
	t.Run("stat failure", func(t *testing.T) {
		dir, write := mk(t)
		write("a", 1)
		old := statFile
		defer func() { statFile = old }()
		statFile = func(*os.File) (os.FileInfo, error) { return nil, boom }
		if _, err := ReadSource(dir); !errors.Is(err, boom) {
			t.Fatal(err)
		}
	})
	t.Run("read failure", func(t *testing.T) {
		dir, write := mk(t)
		write("a", 1)
		old := readFile
		defer func() { readFile = old }()
		readFile = func(*os.File) ([]byte, error) { return nil, boom }
		var pe *os.PathError
		if _, err := ReadSource(dir); !errors.Is(err, boom) || !errors.As(err, &pe) || pe.Op != "read" {
			t.Fatal(err)
		}
	})
	t.Run("not a regular file", func(t *testing.T) {
		dir, _ := mk(t)
		if err := unix.Mkfifo(filepath.Join(dir, "f"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSource(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatal(err)
		}
	})
	t.Run("size bound", func(t *testing.T) {
		dir, write := mk(t)
		write("exact", maxArmoured)
		if got, err := ReadSource(dir); err != nil || len(got[0].Sealed) != maxArmoured {
			t.Fatalf("exactly the bound: %v", err)
		}
		write("exact", maxArmoured+1)
		if _, err := ReadSource(dir); !errors.Is(err, sdcreds.ErrTooLarge) {
			t.Fatalf("one over the bound: %v", err)
		}
	})
}

func TestParseCtlLengthAndDigits(t *testing.T) {
	ok := "fail " + strings.Repeat("a", maxCtlLine-len("fail "))
	if _, err := ParseCtl(ok); err != nil {
		t.Fatalf("a line of exactly %d bytes: %v", maxCtlLine, err)
	}
	if _, err := ParseCtl(ok + "a"); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("a line of %d bytes: %v", maxCtlLine+1, err)
	}
	for _, bad := range []string{"pgid 1_0", "pgid +5", "pgid 5 ", "pgid 0x10", "pgid 05", "pgid 1", "pgid 12345678901", "pgid 2147483648"} {
		if _, err := ParseCtl(bad); !errors.Is(err, ErrCtl) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// slow hands out one byte at a time of an endless line.
type endless struct{ reads int }

func (e *endless) Read(p []byte) (int, error) {
	e.reads++
	p[0] = 'a'
	return 1, nil
}

type failing struct{ sent bool }

func (f *failing) Read(p []byte) (int, error) {
	if !f.sent {
		f.sent = true
		return copy(p, "ab"), nil
	}
	return 0, io.ErrUnexpectedEOF
}

func TestReadCtlBounds(t *testing.T) {
	line := func(n int) string { return "fail " + strings.Repeat("a", n-len("fail ")) }
	// with a tiny buffer, so that the line is assembled from several slices.
	r := bufio.NewReaderSize(strings.NewReader(line(maxCtlLine)+"\n"), 16)
	if c, err := readCtl(r); err != nil || c.Kind != CtlFail {
		t.Fatalf("exactly the bound: %v %v", c, err)
	}
	r = bufio.NewReaderSize(strings.NewReader(line(maxCtlLine+1)+"\n"), 16)
	if _, err := readCtl(r); !errors.Is(err, ErrCtl) {
		t.Fatalf("one over the bound: %v", err)
	}
	// an endless line is refused after a bounded number of reads.
	e := &endless{}
	if _, err := readCtl(bufio.NewReaderSize(e, 16)); !errors.Is(err, ErrCtl) {
		t.Fatalf("endless: %v", err)
	}
	if e.reads > 2*maxCtlLine {
		t.Fatalf("read %d bytes of an endless line", e.reads)
	}
	// a read error ends the read and is returned as it is.
	done := make(chan error, 1)
	go func() {
		_, err := readCtl(bufio.NewReaderSize(&failing{}, 16))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("read error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readCtl does not stop on a read error")
	}
}

func TestPrepareRefusesBeforeTheHelper(t *testing.T) {
	old := geteuid
	defer func() { geteuid = old }()
	geteuid = func() int { return 0 }
	c := goodConfig()
	c.UID = 0
	if _, err := Prepare(context.Background(), c); !errors.Is(err, ErrRootTarget) {
		t.Fatalf("uid 0 target: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Prepare(ctx, goodConfig()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context: %v", err)
	}
}

func TestGuardGroupOfNilSaysSo(t *testing.T) {
	var d *Delivery
	if err := d.GuardGroup(5); err == nil || !strings.Contains(err.Error(), "no delivery") {
		t.Fatal(err)
	}
}

func TestHelperArgsSizeMessage(t *testing.T) {
	_, err := parseHelperArgs([]string{"--owner", "42", "--dir", "/a", "--mib", "x"})
	if err == nil || !strings.Contains(err.Error(), "bad size") {
		t.Fatal(err)
	}
}

func TestAcquireLockSyscallFailures(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	root := fakeTrust(t)
	var pe *os.PathError
	if _, err := AcquireLock(filepath.Join(root, "missing"), "svc"); !errors.Is(err, unix.ENOENT) || !errors.As(err, &pe) || pe.Op != "open" {
		t.Fatalf("missing directory: %v", err)
	}
	boom := errors.New("boom")
	old := fstat
	defer func() { fstat = old }()
	fstat = func(int, *statT) error { return boom }
	if _, err := AcquireLock(root, "svc"); !errors.Is(err, boom) {
		t.Fatalf("fstat failure: %v", err)
	}
}

func TestEnsureBaseCreationFailures(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	boom := errors.New("boom")
	oldO, oldC, oldM := openat, fchown, fchmod
	defer func() { openat, fchown, fchmod = oldO, oldC, oldM }()
	// the first open, of "/", fails and nothing else is tried.
	root := fakeTrust(t)
	n := 0
	openat = func(fd int, p string, flags int, mode uint32) (int, error) {
		n++
		if n == 1 {
			return -1, boom
		}
		return oldO(fd, p, flags, mode)
	}
	if err := EnsureBase(filepath.Join(root, "x")); !errors.Is(err, boom) {
		t.Fatalf("open of /: %v", err)
	}
	openat = oldO
	fchmod = func(int, uint32) error { return boom }
	if err := EnsureBase(filepath.Join(root, "y")); !errors.Is(err, boom) {
		t.Fatalf("fchmod: %v", err)
	}
	fchmod = oldM
	fchown = func(int, int, int) error { return boom }
	if err := EnsureBase(filepath.Join(root, "z")); !errors.Is(err, boom) {
		t.Fatalf("fchown: %v", err)
	}
}
