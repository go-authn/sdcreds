package s6

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds"
)

var errExec = errors.New("exec reached")

// rig is a set of fake Ops that records the order of the calls and acts on a
// plain directory in place of a mount.
type rig struct {
	t     *testing.T
	calls []string
	fail  map[string]error
	env   []string
	argv  []string
	chown map[string][2]int
	// failChown makes the chown of one file (by base name) fail on its own
	failChown map[string]error
	user      User
	// layers counts the mounts stacked on each directory
	layers map[string]int
	// the credentials directory as it is when the command is executed
	files   map[string]string
	perms   map[string]os.FileMode
	dirMode os.FileMode
	// stageMode is the mode of the staging directory when it is moved into place
	stageMode os.FileMode
}

func (r *rig) ops() Ops {
	rec := func(name string) error {
		r.calls = append(r.calls, name)
		return r.fail[name]
	}
	return Ops{
		LookupUser: func(name string) (User, error) {
			if err := rec("lookup"); err != nil {
				return User{}, err
			}
			return r.user, nil
		},
		Unshare: func() error { return rec("unshare") },
		MountRAM: func(dir string) error {
			r.layers[dir]++
			return rec("mount")
		},
		RemountRO: func(string) error { return rec("remount") },
		Move: func(src, dst string) error {
			if err := rec("move"); err != nil {
				return err
			}
			// a bind of the mount on dst, then src is detached
			if st, err := os.Stat(src); err == nil {
				r.stageMode = st.Mode().Perm()
			}
			os.Chmod(src, 0o700) // a plain directory stands in for the mount
			ents, _ := os.ReadDir(src)
			for _, e := range ents {
				if err := os.Rename(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
					return err
				}
			}
			r.layers[dst]++
			r.layers[src]--
			return nil
		},
		Chown: func(p string, uid, gid int) error {
			r.chown[filepath.Base(p)] = [2]int{uid, gid}
			if err := r.failChown[filepath.Base(p)]; err != nil {
				return err
			}
			return rec("chown")
		},
		Unmount: func(dir string) error {
			if err := rec("unmount"); err != nil {
				return err
			}
			if r.layers[dir] == 0 {
				return ErrNotMounted
			}
			r.layers[dir]--
			// the files of a real tmpfs vanish with the mount
			os.Chmod(dir, 0o700)
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				os.Remove(filepath.Join(dir, e.Name()))
			}
			return nil
		},
		Start: func(_ User, argv, env []string) (func() (int, error), error) {
			if err := rec("drop"); err != nil {
				return nil, err
			}
			r.argv, r.env = argv, env
			for _, kv := range env {
				if dir, ok := strings.CutPrefix(kv, EnvVar+"="); ok {
					r.snapshot(dir)
				}
			}
			rec("exec")
			return nil, errExec
		},
	}
}

func (r *rig) snapshot(dir string) {
	r.files, r.perms = map[string]string{}, map[string]os.FileMode{}
	if st, err := os.Stat(dir); err == nil {
		r.dirMode = st.Mode().Perm()
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		st, _ := e.Info()
		r.files[e.Name()], r.perms[e.Name()] = string(b), st.Mode().Perm()
	}
}

func newRig(t *testing.T) *rig {
	return &rig{t: t, fail: map[string]error{}, chown: map[string][2]int{}, failChown: map[string]error{}, layers: map[string]int{}, user: User{UID: 1234, GID: 5678, Groups: []int{5678, 9}}}
}

func nullDecrypt(name string, enc []byte) ([]byte, error) {
	blob, err := sdcreds.Unarmor(enc)
	if err != nil {
		return nil, err
	}
	pt, _, err := sdcreds.Decrypt(blob, sdcreds.DecryptOptions{Name: &name, AllowNull: true})
	return pt, err
}

func seal(t *testing.T, dir, name, secret string) {
	t.Helper()
	blob, err := sdcreds.Encrypt([]byte(secret), sdcreds.EncryptOptions{Key: sdcreds.IDNull, Name: name, Timestamp: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(sdcreds.Armor(blob, 79)), 0o600); err != nil {
		t.Fatal(err)
	}
}

func config(t *testing.T) Config {
	src := t.TempDir()
	seal(t, src, "db-password", "hunter2")
	seal(t, src, "token", "t0k3n")
	return Config{
		Service: "web", User: "svc", BaseDir: t.TempDir(), Source: src,
		Command: []string{"/bin/web", "--serve"},
		Env:     []string{"PATH=/bin", EnvVar + "=/stale", "HOME=/x"},
		Decrypt: nullDecrypt,
	}
}

func TestRunHappyPath(t *testing.T) {
	r, c := newRig(t), config(t)
	c.Unshare = true
	err := Run(c, r.ops())
	if !errors.Is(err, errExec) {
		t.Fatalf("%v", err)
	}
	// The failure of exec itself is undone like any other: unmount comes last.
	// The first unmount clears anything stacked there before; the last two peel
	// the one layer and find nothing below it.
	want := []string{"lookup", "unshare", "unmount", "mount", "chown", "chown", "chown", "remount", "move", "drop", "exec", "unmount", "unmount"}
	if !slices.Equal(r.calls, want) {
		t.Errorf("order of the privileged calls:\n got %v\nwant %v", r.calls, want)
	}
	dir := filepath.Join(c.BaseDir, "web")
	if len(r.files) != 2 {
		t.Errorf("files at exec: %v", r.files)
	}
	for name, content := range map[string]string{"db-password": "hunter2", "token": "t0k3n"} {
		// Windows has no permission bits: only the content is checked there.
		if r.files[name] != content || (runtime.GOOS != "windows" && r.perms[name] != 0o400) {
			t.Errorf("%s: %q %v", name, r.files[name], r.perms[name])
		}
		if r.chown[name] != [2]int{1234, 5678} {
			t.Errorf("%s owner %v", name, r.chown[name])
		}
	}
	if r.chown["mnt"] != [2]int{1234, 5678} {
		t.Errorf("directory owner %v", r.chown["mnt"])
	}
	if runtime.GOOS != "windows" && r.dirMode != 0o700 {
		t.Errorf("directory mode %v", r.dirMode)
	}
	if runtime.GOOS != "windows" && r.stageMode != 0o500 {
		t.Errorf("staged directory mode %v when moved into place", r.stageMode)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("a directory is left after the failed exec")
	}
	if !slices.Equal(r.argv, c.Command) {
		t.Errorf("argv %v", r.argv)
	}
	// The stale variable is replaced, the others are kept.
	if !slices.Equal(r.env, []string{"PATH=/bin", "HOME=/x", EnvVar + "=" + dir}) {
		t.Errorf("env %v", r.env)
	}
}

func TestRunWithoutUnshare(t *testing.T) {
	r, c := newRig(t), config(t)
	if err := Run(c, r.ops()); !errors.Is(err, errExec) || slices.Contains(r.calls, "unshare") {
		t.Errorf("%v %v", err, r.calls)
	}
}

func TestRunValidation(t *testing.T) {
	for name, mod := range map[string]func(*Config){
		"bad service":      func(c *Config) { c.Service = "a/b" },
		"empty service":    func(c *Config) { c.Service = "" },
		"relative base":    func(c *Config) { c.BaseDir = "run/creds" },
		"unclean base":     func(c *Config) { c.BaseDir += "/../x" },
		"trailing slash":   func(c *Config) { c.BaseDir += "/" },
		"no user":          func(c *Config) { c.User = "" },
		"no command":       func(c *Config) { c.Command = nil },
		"missing source":   func(c *Config) { c.Source += "/none" },
		"source is a file": func(c *Config) { c.Source = filepath.Join(c.Source, "token") },
	} {
		r, c := newRig(t), config(t)
		mod(&c)
		err := Run(c, r.ops())
		if err == nil || errors.Is(err, errExec) || len(r.calls) > 1 {
			t.Errorf("%s: %v %v", name, err, r.calls)
		}
		if _, err := os.Stat(filepath.Join(c.BaseDir, "web")); err == nil {
			t.Errorf("%s: a directory was created", name)
		}
	}
}

func TestRunLeavesNothingBehind(t *testing.T) {
	boom := errors.New("boom")
	for _, step := range []string{"lookup", "unshare", "mount", "chown", "remount", "move", "drop"} {
		r, c := newRig(t), config(t)
		c.Unshare = true
		r.fail[step] = boom
		err := Run(c, r.ops())
		if !errors.Is(err, boom) {
			t.Errorf("%s: %v", step, err)
		}
		mounted := slices.Contains(r.calls, "mount") && step != "mount"
		after := r.calls[slices.Index(r.calls, "mount")+1:]
		if step == "mount" || !slices.Contains(r.calls, "mount") {
			after = nil
		}
		if got := slices.Contains(after, "unmount"); got != mounted {
			t.Errorf("%s: unmount=%v mounted=%v %v", step, got, mounted, r.calls)
		}
		if _, err := os.Stat(filepath.Join(c.BaseDir, "web")); err == nil && step != "lookup" && step != "unshare" {
			t.Errorf("%s: the credentials directory is still there", step)
		}
		if slices.Contains(r.calls, "exec") {
			t.Errorf("%s: exec after a failure", step)
		}
	}
}

// Credentials are decrypted before anything is mounted: a bad one leaves the
// system untouched.
func TestRunDecryptsBeforeMounting(t *testing.T) {
	r, c := newRig(t), config(t)
	c.Decrypt = func(name string, enc []byte) ([]byte, error) {
		if name == "token" {
			return nil, errors.New("wrong key")
		}
		return nullDecrypt(name, enc)
	}
	err := Run(c, r.ops())
	if err == nil || !strings.Contains(err.Error(), `"token"`) || !strings.Contains(err.Error(), "wrong key") {
		t.Fatalf("%v", err)
	}
	if slices.Contains(r.calls, "mount") || slices.Contains(r.calls, "unshare") {
		t.Errorf("mounted after a failed decryption: %v", r.calls)
	}
}

func TestPlaintextIsWipedAfterAFailure(t *testing.T) {
	var kept [][]byte
	r, c := newRig(t), config(t)
	c.Decrypt = func(name string, enc []byte) ([]byte, error) {
		pt, err := nullDecrypt(name, enc)
		kept = append(kept, pt)
		return pt, err
	}
	r.fail["mount"] = errors.New("boom")
	if err := Run(c, r.ops()); err == nil {
		t.Fatal("no error")
	}
	if len(kept) != 2 {
		t.Fatalf("%d decryptions", len(kept))
	}
	for _, b := range kept {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Errorf("plaintext left in memory: %q", b)
		}
	}
	// And when the decryption of a later credential fails.
	kept = nil
	c = config(t)
	n := 0
	c.Decrypt = func(name string, enc []byte) ([]byte, error) {
		n++
		if n == 2 {
			return nil, errors.New("second fails")
		}
		pt, err := nullDecrypt(name, enc)
		kept = append(kept, pt)
		return pt, err
	}
	if err := Run(c, newRig(t).ops()); err == nil || len(kept) != 1 || !bytes.Equal(kept[0], make([]byte, len(kept[0]))) {
		t.Errorf("%v %q", err, kept)
	}
}

func TestSourceRefusals(t *testing.T) {
	// A symlink, a directory and a bad name are refused; nothing is mounted.
	for name, mk := range map[string]func(src string){
		"symlink":   func(src string) { os.Symlink(filepath.Join(src, "token"), filepath.Join(src, "link")) },
		"directory": func(src string) { os.Mkdir(filepath.Join(src, "sub"), 0o700) },
		"bad name":  func(src string) { os.WriteFile(filepath.Join(src, "a:b"), []byte("x"), 0o600) },
	} {
		r, c := newRig(t), config(t)
		mk(c.Source)
		if err := Run(c, r.ops()); err == nil || errors.Is(err, errExec) || slices.Contains(r.calls, "mount") {
			t.Errorf("%s: %v %v", name, err, r.calls)
		}
	}
}

func TestEntryAndSizeLimits(t *testing.T) {
	tiny := func(string, []byte) ([]byte, error) { return []byte("x"), nil }
	for _, c := range []struct {
		n  int
		ok bool
	}{{MaxEntries, true}, {MaxEntries + 1, false}} {
		r, cfg := newRig(t), config(t)
		for i := range c.n {
			os.WriteFile(filepath.Join(cfg.Source, fmt.Sprintf("f%d", i)), []byte("x"), 0o600)
		}
		os.Remove(filepath.Join(cfg.Source, "db-password"))
		os.Remove(filepath.Join(cfg.Source, "token"))
		cfg.Decrypt = tiny
		err := Run(cfg, r.ops())
		if c.ok != errors.Is(err, errExec) {
			t.Errorf("%d entries: %v", c.n, err)
		}
	}
	for _, c := range []struct {
		total int
		ok    bool
	}{{MaxTotal, true}, {MaxTotal + 1, false}} {
		r, cfg := newRig(t), config(t)
		cfg.Decrypt = func(name string, _ []byte) ([]byte, error) {
			if name == "token" {
				return make([]byte, 1), nil
			}
			return make([]byte, c.total-1), nil
		}
		err := Run(cfg, r.ops())
		if c.ok != errors.Is(err, errExec) || (!c.ok && !errors.Is(err, sdcreds.ErrTooLarge)) {
			t.Errorf("total %d: %v", c.total, err)
		}
	}
	for _, c := range []struct {
		size int
		ok   bool
	}{{sdcreds.EncryptedMax*4/3 + 4096, true}, {sdcreds.EncryptedMax*4/3 + 4097, false}} {
		r, cfg := newRig(t), config(t)
		cfg.Decrypt = tiny
		if err := os.WriteFile(filepath.Join(cfg.Source, "token"), make([]byte, c.size), 0o600); err != nil {
			t.Fatal(err)
		}
		err := Run(cfg, r.ops())
		if c.ok != errors.Is(err, errExec) || (!c.ok && !errors.Is(err, sdcreds.ErrTooLarge)) {
			t.Errorf("file of %d bytes: %v", c.size, err)
		}
	}
}

func TestFinish(t *testing.T) {
	base := t.TempDir()
	dir := Dir(base, "web")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r := newRig(t)
	if err := Finish("web", base, r.ops()); err != nil || !slices.Equal(r.calls, []string{"unmount"}) {
		t.Fatalf("%v %v", err, r.calls)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("the directory is still there")
	}
	// Idempotent: nothing mounted, nothing there.
	for _, e := range []error{ErrNotMounted, os.ErrNotExist, nil} {
		r := newRig(t)
		r.fail["unmount"] = e
		if err := Finish("web", base, r.ops()); err != nil {
			t.Errorf("second run with %v: %v", e, err)
		}
	}
	// Any other unmount error is reported and the directory is kept.
	os.Mkdir(dir, 0o700)
	r = newRig(t)
	r.fail["unmount"] = errors.New("busy")
	if err := Finish("web", base, r.ops()); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Errorf("%v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("the directory was removed after a failed unmount")
	}
	// A directory that is not empty cannot be removed.
	r = newRig(t)
	os.WriteFile(filepath.Join(dir, "x"), nil, 0o600)
	r.ops() // unmount is the recorder that empties it; use a plain one here
	ops := r.ops()
	ops.Unmount = func(string) error { return ErrNotMounted }
	if err := Finish("web", base, ops); err == nil {
		t.Error("a non-empty directory was reported as released")
	}
	for _, bad := range [][2]string{{"a/b", base}, {"", base}, {"web", "rel"}, {"web", base + "/"}} {
		if err := Finish(bad[0], bad[1], newRig(t).ops()); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
