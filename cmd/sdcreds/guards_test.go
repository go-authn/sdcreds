package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/s6"
)

func TestUnknownUserIsReported(t *testing.T) {
	env(t)
	_, _, err := run(t, "x", "encrypt", "--with-key=null", "--uid=no-such-user-zz9")
	var unknown user.UnknownUserError
	// Windows reports an unmapped account name by its own error type.
	if err == nil || (runtime.GOOS != "windows" && !errors.As(err, &unknown)) {
		t.Errorf("%v", err)
	}
}

func TestScopeOfRefusesNonNumericIDs(t *testing.T) {
	env(t)
	for _, uid := range []string{"S-1-5-21-1-2-3-1001", "4294967296", "-1", ""} {
		if s, err := scopeOf(&user.User{Uid: uid, Username: "u"}); err == nil {
			t.Errorf("%q accepted: %+v", uid, s)
		}
	}
	s, err := scopeOf(&user.User{Uid: "4294967295", Username: "u"})
	if err != nil || s.UID != 4294967295 || s.Username != "u" || s.MachineID == ([16]byte{}) {
		t.Errorf("%+v %v", s, err)
	}
	// A machine id that cannot be read is an error, not a zero id.
	t.Setenv(MachineIDEnv, filepath.Join(t.TempDir(), "none"))
	if s, err := scopeOf(&user.User{Uid: "1", Username: "u"}); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%+v %v", s, err)
	}
}

func TestMachineIDErrorsAreNotIgnored(t *testing.T) {
	needHostFiles(t)
	dir := env(t)
	mustRun(t, "", "setup")
	enc := mustRun(t, "hunter2", "encrypt", "--with-key=null", "--name=c")
	none := filepath.Join(dir, "none")
	t.Setenv(MachineIDEnv, none)
	for name, c := range map[string]struct {
		stdin string
		args  []string
	}{
		"host key":         {"x", []string{"encrypt"}},
		"scope, encrypt":   {"x", []string{"encrypt", "--with-key=null", "--user"}},
		"scope, decrypt":   {enc, []string{"decrypt", "--allow-null", "--name=c", "--user"}},
		"scope by id":      {"x", []string{"encrypt", "--with-key=null", "--uid=" + currentUID(t)}},
		"scoped host mode": {"x", []string{"encrypt", "--user"}},
	} {
		_, _, err := run(t, c.stdin, c.args...)
		if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), none) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func currentUID(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	return u.Uid
}

func TestSetupReportsAFailedCreation(t *testing.T) {
	needHostFiles(t)
	env(t)
	defer func(o func(string, [16]byte) ([]byte, error)) { createHostKey = o }(createHostKey)
	createHostKey = func(string, [16]byte) ([]byte, error) {
		return nil, errors.New("read-only file system")
	}
	out, _, err := run(t, "", "setup")
	if err == nil || !strings.Contains(err.Error(), "read-only file system") || strings.Contains(out, "created") {
		t.Errorf("%q %v", out, err)
	}
}

func TestSetupNamesTheResolvedPath(t *testing.T) {
	needHostFiles(t)
	dir := env(t)
	want := filepath.Join(dir, "secret", "credential.secret")
	for _, verb := range []string{"created", "exists"} {
		if out := mustRun(t, "", "setup"); out != "host secret "+want+" "+verb+"\n" {
			t.Errorf("%s: %q", verb, out)
		}
	}
	explicit := filepath.Join(dir, "other")
	if out := mustRun(t, "", "setup", "--path", explicit); out != "host secret "+explicit+" created\n" {
		t.Errorf("%q", out)
	}
}

func TestGarbageIsNamedAsBase64(t *testing.T) {
	dir := env(t)
	if _, _, err := run(t, "!!not base64!!", "decrypt"); err == nil || !strings.Contains(err.Error(), "base64") {
		t.Errorf("decrypt: %v", err)
	}
	src, base := filepath.Join(dir, "src"), filepath.Join(dir, "run")
	os.MkdirAll(src, 0o700)
	os.MkdirAll(base, 0o700)
	os.WriteFile(filepath.Join(src, "db"), []byte("!!not base64!!"), 0o600)
	defer func(o func() s6.Ops) { s6Ops = o }(s6Ops)
	var calls []string
	s6Ops = fakeOps(&calls, errors.New("exec reached"))
	_, _, err := run(t, "", "s6-run", "--service=web", "--user=svc", "--base-dir="+base, "--source="+src, "--", "/bin/web")
	if err == nil || !strings.Contains(err.Error(), "base64") || strings.Contains(strings.Join(calls, " "), "mount") {
		t.Errorf("s6-run: %v %v", err, calls)
	}
}

func TestReadInputBounds(t *testing.T) {
	cmd := RootCmd()
	for _, c := range []struct {
		in string
		ok bool
	}{{"abcde", true}, {"abcdef", false}, {"", true}} {
		cmd.SetIn(strings.NewReader(c.in))
		b, err := readInput(cmd, "-", 5)
		if c.ok != (err == nil) || (!c.ok && !errors.Is(err, sdcreds.ErrTooLarge)) || (c.ok && string(b) != c.in) {
			t.Errorf("%q: %q %v", c.in, b, err)
		}
	}
	boom := errors.New("pipe broke")
	cmd.SetIn(iotest.ErrReader(boom))
	if _, err := readInput(cmd, "-", 5); !errors.Is(err, boom) || errors.Is(err, sdcreds.ErrTooLarge) {
		t.Errorf("read error: %v", err)
	}
}
