//go:build unix

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/s6"
	"golang.org/x/sys/unix"
)

// A directory that cannot be read, or that goes away, while the path is
// walked is a refusal; so is a parent directory that does not exist.
func TestOpenTrustedWalkFailures(t *testing.T) {
	asOwner(t, uint32(os.Getuid()))
	dir := filepath.Join(ancestorsFrom, "walk")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "key")
	if err := os.WriteFile(file, []byte("k"), 0o400); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	oldOpenat, oldFstat := openat, fstat
	defer func() { openat, fstat = oldOpenat, oldFstat }()

	_, err := openTrusted(filepath.Join(dir, "nodir", "key"))
	var pe *os.PathError
	if !errors.As(err, &pe) || pe.Op != "lstat" {
		t.Errorf("a missing parent: %v", err)
	}
	openat = func(fd int, p string, flags int, mode uint32) (int, error) {
		if p == "/" {
			return -1, boom
		}
		return oldOpenat(fd, p, flags, mode)
	}
	if _, err := openTrusted(file); !errors.Is(err, boom) {
		t.Errorf("no root: %v", err)
	}
	openat = func(fd int, p string, flags int, mode uint32) (int, error) {
		if p == "walk" {
			return -1, boom
		}
		return oldOpenat(fd, p, flags, mode)
	}
	if _, err := openTrusted(file); !errors.Is(err, boom) {
		t.Errorf("a directory that went away: %v", err)
	}
	openat = oldOpenat
	fstat = func(int, *unix.Stat_t) error { return boom }
	if _, err := openTrusted(file); !errors.Is(err, boom) {
		t.Errorf("a directory that cannot be examined: %v", err)
	}
}

// hostSealed prepares a credential "db" sealed with the host key of the files
// that env(t) points at, and returns the source directory, the base directory,
// and the secret and machine id files.
func hostSealed(t *testing.T) (src, base, secret, mid string) {
	t.Helper()
	dir := env(t)
	mid = os.Getenv(MachineIDEnv)
	secret = os.Getenv(sdcreds.HostSecretEnv)
	mustRun(t, "", "setup")
	src, base = filepath.Join(dir, "src"), filepath.Join(dir, "run")
	os.MkdirAll(src, 0o700)
	os.MkdirAll(base, 0o700)
	enc := mustRun(t, "hunter2", "encrypt", "--with-key=host", "--name=db")
	os.WriteFile(filepath.Join(src, "db"), []byte(enc), 0o600)
	return
}

func withOps(t *testing.T) *[]string {
	t.Helper()
	calls := new([]string)
	old := s6Ops
	t.Cleanup(func() { s6Ops = old })
	s6Ops = fakeOps(calls, errors.New("exec reached"))
	return calls
}

func asOwner(t *testing.T, uid uint32) {
	t.Helper()
	old, oldTop := trustedUID, ancestorsFrom
	t.Cleanup(func() { trustedUID, ancestorsFrom = old, oldTop })
	trustedUID = uid
	// The directories above the test's own are not the test's to judge.
	top, err := filepath.EvalSymlinks(filepath.Dir(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	ancestorsFrom = top
}

// The directories above a key file are held to the same rules as the file: a
// directory that group or others can write, or that another user owns, and a
// symbolic link in the path, are refused.
func TestOpenTrustedJudgesTheAncestors(t *testing.T) {
	asOwner(t, uint32(os.Getuid()))
	top := ancestorsFrom
	good := filepath.Join(top, "good", "deeper")
	if err := os.MkdirAll(good, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(good, "key")
	os.WriteFile(file, []byte("k"), 0o400)
	if err := checkTrusted(file); err != nil {
		t.Fatalf("control: %v", err)
	}
	for _, mode := range []os.FileMode{0o775, 0o757} {
		os.Chmod(filepath.Join(top, "good"), mode)
		if err := checkTrusted(file); err == nil || !strings.Contains(err.Error(), "writable by group or others") {
			t.Errorf("ancestor %v: %v", mode, err)
		}
	}
	os.Chmod(filepath.Join(top, "good"), 0o755)
	// the directory of the file itself
	os.Chmod(good, 0o777)
	if err := checkTrusted(file); err == nil {
		t.Error("a writable parent directory was accepted")
	}
	os.Chmod(good, 0o755)
	// another owner (the top is judged too)
	trustedUID = uint32(os.Getuid()) + 1
	if err := checkTrusted(file); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Errorf("foreign owner of an ancestor: %v", err)
	}
	trustedUID = uint32(os.Getuid())
	// a link above the file leads to a directory that is judged: fine when it
	// holds the rules, refused when it does not
	link := filepath.Join(top, "link")
	if err := os.Symlink(filepath.Join(top, "good"), link); err != nil {
		t.Fatal(err)
	}
	if err := checkTrusted(filepath.Join(link, "deeper", "key")); err != nil {
		t.Errorf("a link to a trusted directory: %v", err)
	}
	os.Chmod(filepath.Join(top, "good"), 0o777)
	if err := checkTrusted(filepath.Join(link, "deeper", "key")); err == nil {
		t.Error("a link to a writable directory was accepted")
	}
}

// The privileged path takes its key from the default files or from files named
// by flag, never from the environment of the caller.
func TestS6RunIgnoresTheKeyEnvironment(t *testing.T) {
	src, base, _, _ := hostSealed(t)
	calls := withOps(t)
	_, _, err := run(t, "", "s6-run", "--service=web", "--user=svc", "--base-dir="+base, "--source="+src, "--", "/bin/web")
	if err == nil || strings.Contains(err.Error(), "exec reached") {
		t.Fatalf("a credential was opened with the key the environment names: %v", err)
	}
	if strings.Contains(strings.Join(*calls, " "), "mount") {
		t.Errorf("mounted: %v", *calls)
	}
}

// s6 supervises s6-run, so the exit status of the service is the one of s6-run.
func TestS6RunExitsWithTheStatusOfTheService(t *testing.T) {
	src, base, secret, mid := hostSealed(t)
	asOwner(t, uint32(os.Getuid()))
	calls := withOps(t)
	fake := s6Ops
	for _, code := range []int{0, 7, 143} {
		s6Ops = func() s6.Ops {
			o := fake()
			o.Start = func(s6.User, []string, []string) (func() (int, error), error) {
				return func() (int, error) { return code, nil }, nil
			}
			return o
		}
		got := -1
		old := osExit
		osExit = func(c int) { got = c }
		_, _, err := run(t, "", "s6-run", "--service=web", "--user=svc", "--base-dir="+base, "--source="+src,
			"--secret="+secret, "--machine-id-file="+mid, "--", "/bin/web")
		osExit = old
		if err != nil || (code == 0) != (got == -1) || (code != 0 && got != code) {
			t.Errorf("status %d: exit %d, %v", code, got, err)
		}
	}
	_ = calls
}

func TestS6RunKeyFlags(t *testing.T) {
	src, base, secret, mid := hostSealed(t)
	asOwner(t, uint32(os.Getuid()))
	calls := withOps(t)
	args := func(extra ...string) []string {
		return append([]string{"s6-run", "--service=web", "--user=svc", "--base-dir=" + base, "--source=" + src,
			"--secret=" + secret, "--machine-id-file=" + mid}, append(extra, "--", "/bin/web")...)
	}
	if _, _, err := run(t, "", args()...); err == nil || !strings.Contains(err.Error(), "exec reached") {
		t.Fatalf("explicit files: %v", err)
	}

	// Not owned by the trusted user.
	asOwner(t, uint32(os.Getuid())+1)
	*calls = nil
	_, _, err := run(t, "", args()...)
	if err == nil || !strings.Contains(err.Error(), "--secret") || !strings.Contains(err.Error(), "not owned") {
		t.Errorf("foreign owner of the secret: %v", err)
	}
	if strings.Contains(strings.Join(*calls, " "), "mount") {
		t.Errorf("mounted: %v", *calls)
	}
	asOwner(t, uint32(os.Getuid()))

	// The machine id file is held to the same rules.
	dir := filepath.Dir(mid)
	bad := filepath.Join(dir, "writable-id")
	os.WriteFile(bad, []byte(midText), 0o600)
	os.Chmod(bad, 0o664)
	link := filepath.Join(dir, "link-id")
	os.Symlink(mid, link)
	for name, path := range map[string]string{"group-writable": bad, "symlink": link, "relative": "machine-id", "directory": dir, "missing": filepath.Join(dir, "none")} {
		*calls = nil
		a := append([]string{"s6-run", "--service=web", "--user=svc", "--base-dir=" + base, "--source=" + src,
			"--secret=" + secret, "--machine-id-file=" + path}, "--", "/bin/web")
		_, _, err := run(t, "", a...)
		if err == nil || strings.Contains(err.Error(), "exec reached") || strings.Contains(strings.Join(*calls, " "), "mount") {
			t.Errorf("%s machine id file: %v %v", name, err, *calls)
		}
	}
	// The secret too: a group-writable one is refused by the owner and mode
	// check, whatever else would be said of it.
	os.Chmod(secret, 0o464)
	defer os.Chmod(secret, 0o400)
	if _, _, err := run(t, "", args()...); err == nil || !strings.Contains(err.Error(), "--secret") || !strings.Contains(err.Error(), "writable") {
		t.Errorf("writable secret: %v", err)
	}
}

// Each refusal of openTrusted and readTrustedMachineID is the one that is said.
func TestOpenTrustedRefusals(t *testing.T) {
	_, _, secret, mid := hostSealed(t)
	asOwner(t, uint32(os.Getuid()))
	dir := filepath.Dir(mid)
	unclean := dir + "/../" + filepath.Base(dir) + "/machine-id" // Join would clean it
	if _, err := readTrustedMachineID(unclean); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("unclean path: %v", err)
	}
	if err := checkTrusted(unclean); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("unclean path: %v", err)
	}
	_, err := readTrustedMachineID(filepath.Join(dir, "none"))
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "--machine-id-file") {
		t.Errorf("missing: %v", err)
	}
	if err := checkTrusted(filepath.Join(dir, "none")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing secret: %v", err)
	}
	boom := errors.New("boom")
	oldStat, oldRead := statTrusted, readMachineID
	defer func() { statTrusted, readMachineID = oldStat, oldRead }()
	statTrusted = func(f *os.File) (os.FileInfo, error) { st, _ := f.Stat(); return st, boom } // a usable result beside the error
	if err := checkTrusted(secret); !errors.Is(err, boom) {
		t.Errorf("stat: %v", err)
	}
	statTrusted = oldStat
	readMachineID = func(*os.File) ([]byte, error) { return nil, boom }
	if _, err := readTrustedMachineID(mid); !errors.Is(err, boom) {
		t.Errorf("read: %v", err)
	}
}

// checkTrusted judges a key file the way s6-run does and says nothing else.
func checkTrusted(path string) error {
	f, err := openTrusted(path)
	if err != nil {
		return err
	}
	return f.Close()
}

func TestS6HostKey(t *testing.T) {
	_, _, secret, mid := hostSealed(t)
	asOwner(t, uint32(os.Getuid()))
	k, wipe, err := s6HostKey(secret, mid)
	want, _ := os.ReadFile(secret)
	got, _ := k.HostKey()
	if err != nil || len(want) < 17 || !bytes.Equal(got, want[16:]) {
		t.Fatalf("%v: key %x", err, got)
	}
	// wipe overwrites the key it handed out.
	wipe()
	if !bytes.Equal(got, make([]byte, len(got))) {
		t.Error("the key was not wiped")
	}
	// Nothing in the environment reaches the default files: a different
	// secret in the environment changes nothing.
	t.Setenv(sdcreds.HostSecretEnv, filepath.Join(t.TempDir(), "other"))
	t.Setenv(MachineIDEnv, filepath.Join(t.TempDir(), "other"))
	d, wipe, _ := s6HostKey("", mid)
	wipe()
	if f, ok := d.(sdcreds.HostKeyFile); !ok || f.Path != sdcreds.DefaultHostSecretPath || f.MachineID == ([16]byte{}) {
		t.Errorf("default key source %+v", d)
	}
	// A machine id that is not 32 hex digits is refused.
	short := filepath.Join(filepath.Dir(mid), "short-id")
	os.WriteFile(short, []byte("abcd\n"), 0o444)
	if _, _, err := s6HostKey(secret, short); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("%v", err)
	}
	if _, _, err := s6HostKey("", short); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("default secret: %v", err)
	}
	// A secret judged fit but refused by the library (mode 0444, not 0400) says
	// --secret, and no key comes back.
	loose := filepath.Join(filepath.Dir(secret), "loose")
	os.WriteFile(loose, want, 0o444)
	if k, _, err := s6HostKey(loose, mid); err == nil || k != nil || !strings.Contains(err.Error(), "--secret") {
		t.Errorf("loose secret: %v %v", k, err)
	}
}

// The file that was judged is the file that is read. The path is swapped for
// another host secret (a valid one, owned and moded alike) between the judgment
// and the read; the key must still be the one of the file that was judged.
func TestS6HostKeyIsReadFromTheJudgedDescriptor(t *testing.T) {
	_, _, secret, mid := hostSealed(t)
	asOwner(t, uint32(os.Getuid()))
	judged, _ := os.ReadFile(secret)
	other := bytes.Clone(judged)
	for i := 16; i < len(other); i++ {
		other[i] ^= 0xff
	}
	swapped := false
	defer func(o func(string)) { afterSecretJudged = o }(afterSecretJudged)
	afterSecretJudged = func(path string) {
		if path != secret {
			t.Errorf("seam called for %q", path)
		}
		// The judged file moves aside (so it keeps its one link), and another
		// valid secret takes its name.
		if err := os.Rename(path, path+".judged"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, other, 0o400); err != nil {
			t.Fatal(err)
		}
		swapped = true
	}
	k, wipe, err := s6HostKey(secret, mid)
	defer wipe()
	if err != nil || !swapped {
		t.Fatalf("swapped=%v: %v", swapped, err)
	}
	got, _ := k.HostKey()
	if !bytes.Equal(got, judged[16:]) {
		t.Error("the key was read from the path that replaced the judged file")
	}
	if now, _ := os.ReadFile(secret); !bytes.Equal(now, other) {
		t.Error("control: the path was not swapped")
	}
}

// s6-run wipes the host key once it is done: a credential cannot be opened with
// the key afterwards.
func TestS6RunWipesTheKeyAfterwards(t *testing.T) {
	src, base, secret, mid := hostSealed(t)
	asOwner(t, uint32(os.Getuid()))
	withOps(t)
	var cfg s6.Config
	oldRun := s6Run
	defer func() { s6Run = oldRun }()
	s6Run = func(c s6.Config, o s6.Ops) error { cfg = c; return nil }
	_, _, err := run(t, "", "s6-run", "--service=web", "--user=svc", "--base-dir="+base, "--source="+src,
		"--secret="+secret, "--machine-id-file="+mid, "--", "/bin/web")
	if err != nil || cfg.Decrypt == nil {
		t.Fatalf("%v", err)
	}
	enc, _ := os.ReadFile(filepath.Join(src, "db"))
	if _, err := cfg.Decrypt("db", enc); err == nil {
		t.Error("the credential still opens: the key was not wiped when s6-run ended")
	}
}
