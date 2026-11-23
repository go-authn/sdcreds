//go:build unix

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/s6"
)

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
	old := trustedUID
	t.Cleanup(func() { trustedUID = old })
	trustedUID = uid
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

func TestS6HostKey(t *testing.T) {
	_, _, secret, mid := hostSealed(t)
	asOwner(t, uint32(os.Getuid()))
	k, err := s6HostKey(secret, mid)
	if err != nil || k.Path != secret || k.MachineID == ([16]byte{}) {
		t.Errorf("%+v %v", k, err)
	}
	// Nothing in the environment reaches the default files: a different
	// secret in the environment changes nothing.
	t.Setenv(sdcreds.HostSecretEnv, filepath.Join(t.TempDir(), "other"))
	t.Setenv(MachineIDEnv, filepath.Join(t.TempDir(), "other"))
	k, _ = s6HostKey("", mid)
	if k.Path != sdcreds.DefaultHostSecretPath {
		t.Errorf("secret path %q", k.Path)
	}
	// A machine id that is not 32 hex digits is refused.
	short := filepath.Join(filepath.Dir(mid), "short-id")
	os.WriteFile(short, []byte("abcd\n"), 0o444)
	if _, err := s6HostKey(secret, short); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("%v", err)
	}
}
