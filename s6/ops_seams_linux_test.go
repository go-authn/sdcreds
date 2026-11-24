//go:build linux

package s6

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// swap replaces a seam for the length of the test.
func swap[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	t.Cleanup(func() { *p = old })
	*p = v
}

var boomErr = errors.New("boom")

func TestLookupUserFailures(t *testing.T) {
	ok := func(uid, gid string) {
		swap(t, &userLookup, func(string) (*user.User, error) { return &user.User{Uid: uid, Gid: gid}, nil })
	}
	swap(t, &groupIDs, func(*user.User) ([]string, error) { return []string{"7", "8"}, nil })

	// A user comes back with the error: only the error says it is no user.
	swap(t, &userLookup, func(string) (*user.User, error) { return &user.User{Uid: "1", Gid: "2"}, boomErr })
	if _, err := lookupUser("x"); !errors.Is(err, boomErr) {
		t.Errorf("lookup: %v", err)
	}
	ok("x", "1")
	if _, err := lookupUser("x"); err == nil {
		t.Error("a uid that is not a number")
	}
	ok("1", "x")
	if _, err := lookupUser("x"); err == nil {
		t.Error("a gid that is not a number")
	}
	ok("1", "2")
	swap(t, &groupIDs, func(*user.User) ([]string, error) { return nil, boomErr })
	if _, err := lookupUser("x"); !errors.Is(err, boomErr) {
		t.Errorf("groups: %v", err)
	}
	swap(t, &groupIDs, func(*user.User) ([]string, error) { return []string{"7", "x"}, nil })
	if _, err := lookupUser("x"); err == nil {
		t.Error("a group id that is not a number")
	}
	swap(t, &groupIDs, func(*user.User) ([]string, error) { return []string{"7", "8"}, nil })
	u, err := lookupUser("x")
	if err != nil || u.UID != 1 || u.GID != 2 || !slices.Equal(u.Groups, []int{7, 8}) {
		t.Errorf("%+v %v", u, err)
	}
}

type mountCall struct {
	source, target, fstype string
	flags                  uintptr
}

func recordMounts(t *testing.T, fail func(n int, c mountCall) error) *[]mountCall {
	var calls []mountCall
	swap(t, &sysMount, func(source, target, fstype string, flags uintptr, data string) error {
		c := mountCall{source, target, fstype, flags}
		calls = append(calls, c)
		return fail(len(calls), c)
	})
	return &calls
}

func TestUnshareFailures(t *testing.T) {
	swap(t, &sysUnshare, func(int) error { return boomErr })
	calls := recordMounts(t, func(int, mountCall) error { return nil })
	if err := unshare(); !errors.Is(err, boomErr) || len(*calls) != 0 {
		t.Errorf("%v %v", err, *calls)
	}
	swap(t, &sysUnshare, func(int) error { return nil })
	recordMounts(t, func(int, mountCall) error { return boomErr })
	if err := unshare(); !errors.Is(err, boomErr) {
		t.Errorf("%v", err)
	}
}

func TestMountRAMFailures(t *testing.T) {
	dir := t.TempDir()
	calls := recordMounts(t, func(int, mountCall) error { return nil })
	if err := mountRAM(filepath.Join(dir, "missing")); err == nil || len(*calls) != 0 {
		t.Errorf("a directory that is not there: %v %v", err, *calls)
	}
	if err := mountRAM(dir); err != nil || len(*calls) != 1 || (*calls)[0].fstype != "tmpfs" {
		t.Errorf("%v %v", err, *calls)
	}
	// A kernel that does not know noswap: the ramfs.
	calls = recordMounts(t, func(n int, _ mountCall) error {
		if n == 1 {
			return syscall.EINVAL
		}
		return nil
	})
	if err := mountRAM(dir); err != nil || len(*calls) != 2 || (*calls)[1].fstype != "ramfs" {
		t.Errorf("%v %v", err, *calls)
	}
	// Any other refusal is final: nothing else is tried.
	calls = recordMounts(t, func(int, mountCall) error { return syscall.EPERM })
	if err := mountRAM(dir); !errors.Is(err, syscall.EPERM) || len(*calls) != 1 {
		t.Errorf("%v %v", err, *calls)
	}
}

func TestRemountROFailures(t *testing.T) {
	dir := t.TempDir()
	calls := recordMounts(t, func(int, mountCall) error { return nil })
	if err := remountRO(filepath.Join(dir, "missing")); err == nil || len(*calls) != 0 {
		t.Errorf("%v %v", err, *calls)
	}
	if err := remountRO(dir); err != nil || len(*calls) != 1 {
		t.Errorf("%v %v", err, *calls)
	}
	recordMounts(t, func(int, mountCall) error { return boomErr })
	if err := remountRO(dir); !errors.Is(err, boomErr) {
		t.Errorf("%v", err)
	}
}

func TestMoveFailures(t *testing.T) {
	root := t.TempDir()
	src, dst := filepath.Join(root, "src"), filepath.Join(root, "dst")
	for _, d := range []string{src, dst} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var unmounted []string
	swap(t, &sysUnmount, func(target string, _ int) error { unmounted = append(unmounted, target); return nil })
	calls := recordMounts(t, func(int, mountCall) error { return nil })

	if err := move(filepath.Join(root, "missing"), dst); err == nil || len(*calls) != 0 {
		t.Errorf("no source: %v %v", err, *calls)
	}
	if err := move(src, filepath.Join(root, "missing")); err == nil || len(*calls) != 0 {
		t.Errorf("no destination: %v %v", err, *calls)
	}
	// A bind that fails leaves the source where it is: it is not detached.
	recordMounts(t, func(int, mountCall) error { return boomErr })
	if err := move(src, dst); !errors.Is(err, boomErr) || len(unmounted) != 0 {
		t.Errorf("%v %v", err, unmounted)
	}
	calls = recordMounts(t, func(int, mountCall) error { return nil })
	if err := move(src, dst); err != nil || len(*calls) != 1 || (*calls)[0].flags != syscall.MS_BIND || !slices.Equal(unmounted, []string{src}) {
		t.Errorf("%v %v %v", err, *calls, unmounted)
	}
}

func TestUnmountErrors(t *testing.T) {
	for _, c := range []struct {
		in   error
		want error
	}{{syscall.EINVAL, ErrNotMounted}, {syscall.ENOENT, ErrNotMounted}, {syscall.EPERM, syscall.EPERM}, {nil, nil}} {
		swap(t, &sysUnmount, func(string, int) error { return c.in })
		if err := unmount("/x"); !errors.Is(err, c.want) && err != c.want {
			t.Errorf("%v: %v", c.in, err)
		}
	}
}

func TestFSTypeFailures(t *testing.T) {
	if _, err := fsType(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("a directory that is not there")
	}
}

func TestMountSourceFailures(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := mountSource(filepath.Join(dir, "missing")); err == nil {
		t.Error("a directory that is not there")
	}
	swap(t, &mountinfoPath, filepath.Join(dir, "no-table"))
	if _, _, err := mountSource(dir); err == nil {
		t.Error("a table that cannot be read")
	}
	table := filepath.Join(dir, "table")
	if err := os.WriteFile(table, []byte("36 1 0:30 / "+dir+" rw - "+MountTag+" "+MountTag+" rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	mountinfoPath = table
	src, mounted, err := mountSource(dir)
	if err != nil || !mounted || src != MountTag {
		t.Errorf("%q %v %v", src, mounted, err)
	}
}

// rawLog records the identity calls of a thread and fails the ones that fail
// says so for; nothing real is changed.
type rawCall struct{ trap, id uintptr }

func fakeRaw(t *testing.T, fail func(n int, c rawCall) bool) *[]rawCall {
	var calls []rawCall
	swap(t, &sysRaw, func(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
		c := rawCall{trap, a1}
		calls = append(calls, c)
		if fail(len(calls), c) {
			return 0, 0, syscall.EPERM
		}
		return 0, 0, 0
	})
	return &calls
}

func TestRawIDCalls(t *testing.T) {
	fakeRaw(t, func(int, rawCall) bool { return true })
	if err := rawSetres(trapSetresuid, 1, 0); !errors.Is(err, syscall.EPERM) {
		t.Errorf("setres: %v", err)
	}
	if err := rawSetgroups([]int{1, 2}); !errors.Is(err, syscall.EPERM) {
		t.Errorf("setgroups: %v", err)
	}
	if err := rawSetgroups(nil); !errors.Is(err, syscall.EPERM) {
		t.Errorf("setgroups, none: %v", err)
	}
	fakeRaw(t, func(int, rawCall) bool { return false })
	if err := rawSetres(trapSetresuid, 1, 0); err != nil {
		t.Errorf("setres: %v", err)
	}
	if err := rawSetgroups([]int{1, 2}); err != nil {
		t.Errorf("setgroups: %v", err)
	}
}

func TestCanExecRefusals(t *testing.T) {
	u := User{UID: 12345, GID: 12345}
	run := func(path string) (err error) {
		onThread(func() { err = canExec(path, u) })
		return err
	}
	dir := t.TempDir()
	prog := filepath.Join(dir, "prog")
	if err := os.WriteFile(prog, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The thread must be given back to root whatever happened: setgroups of
	// the user, then the user's ids, then the three restoring calls.
	calls := fakeRaw(t, func(int, rawCall) bool { return false })
	if err := run(prog); err != nil || len(*calls) != 6 {
		t.Fatalf("control: %v %v", err, *calls)
	}
	swap(t, &sysAccess, func(string, uint32) error { return boomErr })
	if err := run(prog); !errors.Is(err, boomErr) {
		t.Errorf("access: %v", err)
	}
	swap(t, &sysAccess, func(string, uint32) error { return nil })
	if err := run(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	if err := run(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}

	// Each step that fails is the error, and the thread is still restored.
	for name, fail := range map[string]func(n int, c rawCall) bool{
		"setgroups": func(n int, c rawCall) bool { return n == 1 },
		"setresgid": func(n int, c rawCall) bool { return c.trap == trapSetresgid && c.id != 0 },
	} {
		calls := fakeRaw(t, fail)
		if err := run(prog); !errors.Is(err, syscall.EPERM) {
			t.Errorf("%s: %v", name, err)
		}
		if len(*calls) < 4 {
			t.Errorf("%s: the thread was not restored: %v", name, *calls)
		}
	}
	// A thread that cannot get root back is reported.
	fakeRaw(t, func(n int, c rawCall) bool { return c.trap == trapSetresuid && c.id == 0 })
	if err := run(prog); err == nil || !strings.Contains(err.Error(), "restore") {
		t.Errorf("restore: %v", err)
	}
	// And the account whose groups cannot be read is no user at all.
	fakeRaw(t, func(int, rawCall) bool { return false })
	swap(t, &sysGetgroups, func() ([]int, error) { return nil, boomErr })
	if err := run(prog); !errors.Is(err, boomErr) {
		t.Errorf("getgroups: %v", err)
	}
}

func TestPrctlErrno(t *testing.T) {
	swap(t, &sysRaw6, func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
		return 0, 0, syscall.EPERM
	})
	if _, err := prctl(1, 2); !errors.Is(err, syscall.EPERM) {
		t.Errorf("%v", err)
	}
	swap(t, &sysRaw6, func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
		return 5, 0, 0
	})
	if v, err := prctl(1, 2); err != nil || v != 5 {
		t.Errorf("%v %v", v, err)
	}
}

func TestRestrictThreadFailures(t *testing.T) {
	var calls [][2]uintptr
	fake := func(failAt func(opt, c uintptr) error) {
		calls = nil
		swap(t, &prctlCall, func(opt, arg uintptr) (uintptr, error) {
			calls = append(calls, [2]uintptr{opt, arg})
			return 0, failAt(opt, arg)
		})
	}
	fake(func(opt, c uintptr) error {
		if opt == prSetNoNewPrivs {
			return syscall.EPERM
		}
		return nil
	})
	if err := restrictThread(); err == nil || !strings.Contains(err.Error(), "no_new_privs") || len(calls) != 1 {
		t.Errorf("%v %v", err, calls)
	}
	// The end of the capabilities of the kernel is not an error.
	fake(func(opt, c uintptr) error {
		if opt == prCapbsetRead && c == 3 {
			return syscall.EINVAL
		}
		return nil
	})
	if err := restrictThread(); err != nil {
		t.Errorf("%v", err)
	}
	drops := 0
	for _, c := range calls {
		if c[0] == prCapbsetDrop {
			drops++
		}
	}
	if drops != 3 {
		t.Errorf("%d capabilities dropped: %v", drops, calls)
	}
	// Any other failure of the read, or of the drop, is final.
	for _, bad := range []uintptr{prCapbsetRead, prCapbsetDrop} {
		fake(func(opt, c uintptr) error {
			if opt == bad && c == 1 {
				return syscall.EPERM
			}
			return nil
		})
		if err := restrictThread(); err == nil || !strings.Contains(err.Error(), "capability bounding set") {
			t.Errorf("%d: %v", bad, err)
		}
		for _, c := range calls {
			if c[1] > 1 && c[0] != prCapbsetRead && c[0] != prSetNoNewPrivs {
				t.Errorf("%d: went on after the failure: %v", bad, calls)
			}
		}
	}
}
