//go:build unix

package s6

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// A strict umask of the caller must not make the base unreadable to the service
// user: every directory Run creates gets 0755 whatever the umask, and one that
// exists is left alone.
func TestBaseModeIgnoresUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	r, c := newRig(t), config(t)
	top := filepath.Join(c.BaseDir, "run")
	c.BaseDir = filepath.Join(top, "sdcreds")
	if err := Run(c, r.ops()); !errors.Is(err, errExec) {
		t.Fatal(err)
	}
	for _, d := range []string{top, c.BaseDir} {
		if st, err := os.Stat(d); err != nil || st.Mode().Perm() != 0o755 {
			t.Errorf("%s: %v %v", d, st, err)
		}
	}
}

func TestExistingBaseModeIsKept(t *testing.T) {
	r, c := newRig(t), config(t)
	if err := os.Chmod(c.BaseDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := Run(c, r.ops()); !errors.Is(err, errExec) {
		t.Fatal(err)
	}
	if st, err := os.Stat(c.BaseDir); err != nil || st.Mode().Perm() != 0o750 {
		t.Errorf("%v %v", st, err)
	}
}

// A base that cannot be created is the error of checkBase, not a panic.
func TestBaseThatCannotBeCreated(t *testing.T) {
	r, c := newRig(t), config(t)
	file := filepath.Join(c.BaseDir, "file")
	os.WriteFile(file, nil, 0o600)
	c.BaseDir = filepath.Join(file, "sdcreds")
	err := Run(c, r.ops())
	if err == nil || errors.Is(err, errExec) || slices.Contains(r.calls, "mount") {
		t.Errorf("%v %v", err, r.calls)
	}
}

// A mode that cannot be set stops Run before anything is mounted.
func TestBaseModeFailureStopsRun(t *testing.T) {
	r, c := newRig(t), config(t)
	c.BaseDir = filepath.Join(c.BaseDir, "new")
	boom := errors.New("fchmod failed")
	old := fchmodDir
	defer func() { fchmodDir = old }()
	fchmodDir = func(string, os.FileMode) error { return boom }
	if err := Run(c, r.ops()); !errors.Is(err, boom) || slices.Contains(r.calls, "mount") {
		t.Errorf("%v %v", err, r.calls)
	}
}

// The mode is set through a descriptor that does not follow a link.
func TestFchmodDirRefusesALink(t *testing.T) {
	dir := t.TempDir()
	target, link := filepath.Join(dir, "t"), filepath.Join(dir, "l")
	os.Mkdir(target, 0o700)
	os.Symlink(target, link)
	if err := fchmodDir(link, 0o755); err == nil {
		t.Error("followed a link")
	}
	if st, _ := os.Stat(target); st.Mode().Perm() != 0o700 {
		t.Errorf("target mode %v", st.Mode().Perm())
	}
	if err := fchmodDir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(target); st.Mode().Perm() != 0o755 {
		t.Errorf("target mode %v", st.Mode().Perm())
	}
}

// What root may execute and the service user may not is refused before
// anything is mounted, whether or not the mount is private.
func TestCommandThatTheServiceUserCannotExecute(t *testing.T) {
	for _, unshare := range []bool{false, true} {
		r, c := newRig(t), config(t)
		c.Unshare = unshare
		ops := r.ops()
		ops.Resolve = func(s string) (string, error) { return "/resolved/" + s, nil }
		deny := errors.New("permission denied")
		var gotPath string
		var gotUser User
		ops.CanExec = func(p string, u User) error { gotPath, gotUser = p, u; return deny }
		err := Run(c, ops)
		if !errors.Is(err, deny) || !strings.Contains(err.Error(), `"/bin/web"`) || !strings.Contains(err.Error(), "svc") {
			t.Fatalf("%v", err)
		}
		if gotPath != "/resolved//bin/web" || gotUser.UID != r.user.UID {
			t.Errorf("CanExec(%q, %+v)", gotPath, gotUser)
		}
		for _, step := range []string{"mount", "unshare", "drop", "exec", "unmount"} {
			if slices.Contains(r.calls, step) {
				t.Errorf("%s reached: %v", step, r.calls)
			}
		}
	}
}

// Without Resolve the command is judged as given.
func TestCanExecWithoutResolve(t *testing.T) {
	r, c := newRig(t), config(t)
	ops := r.ops()
	var gotPath string
	ops.CanExec = func(p string, u User) error { gotPath = p; return nil }
	if err := Run(c, ops); !errors.Is(err, errExec) {
		t.Fatal(err)
	}
	if gotPath != "/bin/web" {
		t.Errorf("CanExec path %q", gotPath)
	}
}

// A service that was started is waited for, and the credentials are taken away
// after it ends, by the process that still has its privileges.
func TestRunWaitsThenCleansUp(t *testing.T) {
	boom := errors.New("wait failed")
	for _, c := range []struct {
		name string
		code int
		err  error
	}{{"exit 0", 0, nil}, {"exit 3", 3, nil}, {"wait error", 0, boom}} {
		r, cfg := newRig(t), config(t)
		ops := r.ops()
		ops.Start = func(User, []string, []string) (func() (int, error), error) {
			r.calls = append(r.calls, "started")
			return func() (int, error) {
				r.calls = append(r.calls, "waited")
				return c.code, c.err
			}, nil
		}
		err := Run(cfg, ops)
		var ee *ExitError
		switch {
		case c.err != nil:
			if !errors.Is(err, boom) {
				t.Errorf("%s: %v", c.name, err)
			}
		case c.code != 0:
			if !errors.As(err, &ee) || ee.Code != c.code || ee.Error() == "" {
				t.Errorf("%s: %v", c.name, err)
			}
		case err != nil:
			t.Errorf("%s: %v", c.name, err)
		}
		i := slices.Index(r.calls, "waited")
		if i < 0 || !slices.Contains(r.calls[i:], "unmount") {
			t.Errorf("%s: the credentials are taken away after the service ends: %v", c.name, r.calls)
		}
		if _, err := os.Stat(Dir(cfg.BaseDir, "web")); err == nil {
			t.Errorf("%s: the credentials directory is still there", c.name)
		}
	}
}

// A program that cannot be started leaves nothing mounted, and is never waited for.
func TestFailedStartTakesTheCredentialsAway(t *testing.T) {
	r, c := newRig(t), config(t)
	ops := r.ops()
	bad := errors.New("exec format error")
	ops.Start = func(User, []string, []string) (func() (int, error), error) { return nil, bad }
	err := Run(c, ops)
	if !errors.Is(err, bad) || !slices.Contains(r.calls, "unmount") || r.layers[Dir(c.BaseDir, "web")] != 0 {
		t.Errorf("%v %v %v", err, r.calls, r.layers)
	}
	if _, err := os.Stat(Dir(c.BaseDir, "web")); err == nil {
		t.Error("the credentials directory is still there")
	}
}

// Only a mount this package made is detached.
func TestFinishDetachesOnlyItsOwnMounts(t *testing.T) {
	for _, c := range []struct {
		name    string
		src     string
		mounted bool
		err     error
		unmount bool
		want    error
	}{
		{"ours", MountTag, true, nil, true, nil},
		{"foreign", "tmpfs", true, nil, false, ErrForeignMount},
		{"another name", "sdcreds2", true, nil, false, ErrForeignMount},
		{"empty source", "", true, nil, false, ErrForeignMount},
		{"not a mount", "", false, nil, false, nil},
		{"unreadable table", "", false, os.ErrPermission, false, os.ErrPermission},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			os.Mkdir(Dir(base, "web"), 0o700)
			r := newRig(t)
			r.layers[Dir(base, "web")] = 1
			ops := r.ops()
			ops.MountSource = func(string) (string, bool, error) {
				if c.src == MountTag && r.layers[Dir(base, "web")] == 0 {
					return "", false, nil
				}
				return c.src, c.mounted, c.err
			}
			err := Finish("web", base, ops)
			if !errors.Is(err, c.want) || (c.want == nil) != (err == nil) {
				t.Fatalf("%v, want %v", err, c.want)
			}
			if got := slices.Contains(r.calls, "unmount"); got != c.unmount {
				t.Errorf("unmount called: %v", got)
			}
			if !c.unmount && r.layers[Dir(base, "web")] != 1 {
				t.Error("a foreign mount was detached")
			}
		})
	}
}

// A foreign memory file system on the directory of a service stops Run too, and
// nothing is mounted over it.
func TestRunRefusesAForeignMount(t *testing.T) {
	r, c := newRig(t), config(t)
	dir := Dir(c.BaseDir, "web")
	r.layers[dir] = 1
	ops := r.ops()
	ops.MountSource = func(string) (string, bool, error) { return "tmpfs", true, nil }
	err := Run(c, ops)
	if !errors.Is(err, ErrForeignMount) {
		t.Fatalf("%v", err)
	}
	if slices.Contains(r.calls, "mount") || slices.Contains(r.calls, "unmount") || r.layers[dir] != 1 {
		t.Errorf("%v %v", r.calls, r.layers)
	}
}

// A file system that is not a memory file system is never asked about its source.
func TestForeignTypeIsLeftAloneBeforeTheSource(t *testing.T) {
	base := t.TempDir()
	os.Mkdir(Dir(base, "web"), 0o700)
	r := newRig(t)
	ops := r.ops()
	ops.FSType = func(string) (string, error) { return "0xef53", nil }
	ops.MountSource = func(string) (string, bool, error) { t.Error("source read"); return "", false, nil }
	if err := Finish("web", base, ops); err != nil {
		t.Fatal(err)
	}
}

func TestMountSourceIn(t *testing.T) {
	const table = `22 1 0:21 / /run rw,nosuid shared:5 - tmpfs tmpfs rw,size=100k
60 22 0:50 / /run/sdcreds/web ro,nosuid,nodev,noexec,nosymfollow - tmpfs sdcreds rw,noswap
61 22 0:51 / /run/sdcreds/other rw,nosuid master:1 shared:7 - tmpfs foreign rw
62 22 0:52 / /run/with\040space ro - tmpfs sdcreds rw
63 22 0:53 / /run/stack ro - tmpfs sdcreds rw
64 22 0:54 / /run/stack rw - tmpfs top rw
garbage
65 22 0:55 / /run/short rw -
`
	for _, c := range []struct {
		dir     string
		src     string
		mounted bool
	}{
		{"/run", "tmpfs", true},
		{"/run/sdcreds/web", "sdcreds", true},
		{"/run/sdcreds/other", "foreign", true},
		{"/run/with space", "sdcreds", true},
		{"/run/stack", "top", true}, // the topmost layer answers
		{"/run/short", "", false},
		{"/run/sdcreds", "", false},
		{"/run/sdcreds/we", "", false},
	} {
		src, mounted := mountSourceIn(table, c.dir)
		if src != c.src || mounted != c.mounted {
			t.Errorf("%s: %q %v", c.dir, src, mounted)
		}
	}
}

func TestUnescapeMountinfo(t *testing.T) {
	for in, want := range map[string]string{
		`plain`:        "plain",
		`a\040b`:       "a b",
		`\134`:         `\`,
		`tab\011x`:     "tab\tx",
		`end\04`:       `end\04`,
		`bad\zzzx`:     `bad\zzzx`,
		`\040`:         " ",
		`x\040\040y`:   "x  y",
		`\0400`:        " 0",
		`trailing\`:    `trailing\`,
		`\040\`:        ` \`,
		`over\777flow`: `over\777flow`,
	} {
		if got := unescapeMountinfo(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
