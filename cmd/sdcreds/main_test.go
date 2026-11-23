package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/s6"
)

const midText = "0123456789abcdef0123456789abcdef\n"

// env points the host secret and the machine id at a temporary directory.
func env(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mid := filepath.Join(dir, "machine-id")
	if err := os.WriteFile(mid, []byte(midText), 0o444); err != nil {
		t.Fatal(err)
	}
	t.Setenv(MachineIDEnv, mid)
	t.Setenv(sdcreds.HostSecretEnv, filepath.Join(dir, "secret", "credential.secret"))
	return dir
}

func needHostFiles(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the host secret needs a unix file system")
	}
}

// run executes the command line and returns stdout, stderr and the error.
func run(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	return runIn(t, strings.NewReader(stdin), args...)
}

// runIn is run with any reader; a panic is an error, so that a missing guard
// fails the assertion about what it should have said.
func runIn(t *testing.T, stdin io.Reader, args ...string) (so, se string, err error) {
	t.Helper()
	cmd := RootCmd()
	var out, errb bytes.Buffer
	cmd.SetIn(stdin)
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
		so, se = out.String(), errb.String()
	}()
	err = cmd.Execute()
	return
}

func mustRun(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	out, _, err := run(t, stdin, args...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out
}

func TestNullRoundTripThroughFiles(t *testing.T) {
	dir := env(t)
	in, enc := filepath.Join(dir, "plain"), filepath.Join(dir, "db-password")
	os.WriteFile(in, []byte("hunter2\n"), 0o600)
	mustRun(t, "", "encrypt", "--with-key=null", in, enc)
	text, _ := os.ReadFile(enc)
	if !strings.HasSuffix(string(text), "\n") || strings.Contains(strings.TrimSuffix(string(text), "\n"), "\n\n") {
		t.Errorf("armour: %q", text)
	}
	for _, l := range strings.Split(strings.TrimSuffix(string(text), "\n"), "\n") {
		if len(l) > 79 {
			t.Errorf("line of %d columns", len(l))
		}
	}
	// The name defaults to the base name of the output and is enforced on the way back.
	out := filepath.Join(dir, "out")
	mustRun(t, "", "decrypt", "--allow-null", enc, out)
	if b, _ := os.ReadFile(out); string(b) != "hunter2\n" {
		t.Errorf("%q", b)
	}
	if st, _ := os.Stat(out); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode())
	}
	renamed := filepath.Join(dir, "other")
	os.Rename(enc, renamed)
	if _, _, err := run(t, "", "decrypt", "--allow-null", renamed, out); !errors.Is(err, sdcreds.ErrNameMismatch) {
		t.Errorf("renamed credential: %v", err)
	}
	// --name overrides, --name= disables.
	mustRun(t, "", "decrypt", "--allow-null", "--name=db-password", renamed, out)
	mustRun(t, "", "decrypt", "--allow-null", "--name=", renamed, out)
	if _, _, err := run(t, "", "decrypt", "--allow-null", "--name=nope", renamed, out); !errors.Is(err, sdcreds.ErrNameMismatch) {
		t.Errorf("wrong --name: %v", err)
	}
}

func TestStdinStdout(t *testing.T) {
	env(t)
	text := mustRun(t, "secret", "encrypt", "--with-key=null", "-", "-")
	if got := mustRun(t, text, "decrypt", "--allow-null"); got != "secret" {
		t.Errorf("%q", got)
	}
	// No name is embedded for stdout, so any --name is accepted on the way back
	// only when it matches: here none is expected.
	blob, _ := sdcreds.Unarmor([]byte(text))
	if h, err := sdcreds.Parse(blob); err != nil || h.ID != sdcreds.IDNull {
		t.Errorf("%+v %v", h, err)
	}
	if _, md, err := sdcreds.Decrypt(blob, sdcreds.DecryptOptions{AllowNull: true}); err != nil || md.Name != "" {
		t.Errorf("%+v %v", md, err)
	}
	if got := mustRun(t, mustRun(t, "x", "encrypt", "--with-key=null", "--name=nm"), "decrypt", "--allow-null", "--name=nm"); got != "x" {
		t.Errorf("%q", got)
	}
}

func TestHostAndScopedModes(t *testing.T) {
	needHostFiles(t)
	env(t)
	if out := mustRun(t, "", "setup"); !strings.Contains(out, "created") {
		t.Errorf("%q", out)
	}
	if out := mustRun(t, "", "setup"); !strings.Contains(out, "exists") {
		t.Errorf("setup is not idempotent: %q", out)
	}
	for _, mode := range [][]string{{"--with-key=host"}, {"-H"}, {}, {"--with-key=auto"}} {
		enc := mustRun(t, "pw", append([]string{"encrypt", "--name=c"}, mode...)...)
		blob, _ := sdcreds.Unarmor([]byte(enc))
		if h, _ := sdcreds.Parse(blob); h == nil || h.ID != sdcreds.IDHost {
			t.Errorf("%v: %+v", mode, h)
		}
		if got := mustRun(t, enc, "decrypt", "--name=c"); got != "pw" {
			t.Errorf("%v: %q", mode, got)
		}
	}
	u, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	for _, scope := range []string{"--user", "--uid=" + u.Uid, "--uid=" + u.Username} {
		enc := mustRun(t, "pw", "encrypt", "--name=c", scope)
		blob, _ := sdcreds.Unarmor([]byte(enc))
		if h, _ := sdcreds.Parse(blob); h == nil || h.ID != sdcreds.IDHostScoped {
			t.Errorf("%s: %+v", scope, h)
		}
		if got := mustRun(t, enc, "decrypt", "--name=c", scope); got != "pw" {
			t.Errorf("%s: %q", scope, got)
		}
		if _, _, err := run(t, enc, "decrypt", "--name=c"); !errors.Is(err, sdcreds.ErrScope) {
			t.Errorf("%s without scope: %v", scope, err)
		}
	}
	// The secret is bound to the machine id.
	mid := os.Getenv(MachineIDEnv)
	if err := os.Chmod(mid, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mid, []byte("ffffffffffffffffffffffffffffffff\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, mustRun(t, "x", "encrypt", "--with-key=null"), "decrypt", "--allow-null"); err != nil {
		t.Errorf("a null credential needs no host key: %v", err)
	}
	if _, _, err := run(t, "x", "encrypt"); !errors.Is(err, sdcreds.ErrHostKeyMachine) {
		t.Errorf("secret of another machine: %v", err)
	}
}

func TestNullFlags(t *testing.T) {
	env(t)
	for _, args := range [][]string{
		{"encrypt", "--with-key=null", "--refuse-null"},
	} {
		if _, _, err := run(t, "x", args...); !errors.Is(err, sdcreds.ErrNullRefused) {
			t.Errorf("%v: %v", args, err)
		}
	}
	enc := mustRun(t, "x", "encrypt", "--with-key=null")
	if _, _, err := run(t, enc, "decrypt", "--refuse-null"); !errors.Is(err, sdcreds.ErrNullRefused) {
		t.Errorf("%v", err)
	}
	for _, c := range []string{"encrypt", "decrypt"} {
		if _, _, err := run(t, "x", c, "--allow-null", "--refuse-null"); !errors.Is(err, sdcreds.ErrInvalid) {
			t.Errorf("%s with both: %v", c, err)
		}
	}
}

func TestPretty(t *testing.T) {
	env(t)
	out := mustRun(t, strings.Repeat("a", 200), "encrypt", "--with-key=null", "--name=web", "--pretty")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if lines[0] != `SetCredentialEncrypted=web: \` {
		t.Fatalf("%q", lines[0])
	}
	if len(lines) < 3 {
		t.Fatalf("%q", out)
	}
	var b64 strings.Builder
	for i, l := range lines[1:] {
		last := i == len(lines)-2
		if !strings.HasPrefix(l, "        ") || strings.HasSuffix(l, `\`) == last {
			t.Errorf("line %d: %q", i, l)
		}
		body := strings.TrimSuffix(strings.TrimPrefix(l, "        "), ` \`)
		if (!last && len(body) != sdcreds.ArmorWidthPretty) || len(body) > sdcreds.ArmorWidthPretty || len(body) == 0 {
			t.Errorf("line %d has %d columns", i, len(body))
		}
		b64.WriteString(body)
	}
	blob, err := sdcreds.Unarmor([]byte(b64.String()))
	if err != nil {
		t.Fatal(err)
	}
	if pt, _, err := sdcreds.Decrypt(blob, sdcreds.DecryptOptions{AllowNull: true}); err != nil || len(pt) != 200 {
		t.Errorf("%v", err)
	}
}

func TestPrettyWithoutName(t *testing.T) {
	env(t)
	out := mustRun(t, strings.Repeat("a", 200), "encrypt", "--with-key=null", "--pretty")
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, " ") || strings.Contains(l, "=") && i == 0 && strings.HasPrefix(l, "SetCredential") {
			t.Errorf("line %d: %q", i, l)
		}
		if i < len(lines)-1 && len(l) != sdcreds.ArmorWidthPretty || len(l) > sdcreds.ArmorWidthPretty {
			t.Errorf("line %d has %d columns", i, len(l))
		}
	}
	blob, err := sdcreds.Unarmor([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if pt, _, err := sdcreds.Decrypt(blob, sdcreds.DecryptOptions{AllowNull: true}); err != nil || len(pt) != 200 {
		t.Errorf("%v", err)
	}
}

func TestTimes(t *testing.T) {
	env(t)
	past := mustRun(t, "x", "encrypt", "--with-key=null", "--timestamp=@1000", "--not-after=@2000")
	if _, _, err := run(t, past, "decrypt", "--allow-null"); !errors.Is(err, sdcreds.ErrExpired) {
		t.Errorf("expired: %v", err)
	}
	future := mustRun(t, "x", "encrypt", "--with-key=null", "--timestamp=2020-01-01T00:00:00Z", "--not-after=2999-01-01T00:00:00Z")
	if got := mustRun(t, future, "decrypt", "--allow-null"); got != "x" {
		t.Errorf("%q", got)
	}
	blob, _ := sdcreds.Unarmor([]byte(future))
	_, md, _ := sdcreds.Decrypt(blob, sdcreds.DecryptOptions{AllowNull: true})
	if md.Timestamp != 1577836800*1_000_000 || md.NotAfter != 32472144000*1_000_000 {
		t.Errorf("%+v", md)
	}
	for _, bad := range []string{"--timestamp=yesterday", "--not-after=@", "--timestamp=@-1", "--not-after=@99999999999999999999", "--timestamp=1970-01-01T00:00:00+01:00", "--timestamp=@5000000000000000"} {
		if _, _, err := run(t, "x", "encrypt", "--with-key=null", bad); !errors.Is(err, sdcreds.ErrInvalid) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if _, _, err := run(t, "x", "encrypt", "--with-key=null", "--timestamp=@2000", "--not-after=@1000"); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("not-after before timestamp: %v", err)
	}
}

func TestUnsupportedModes(t *testing.T) {
	env(t)
	var unsup *sdcreds.UnsupportedModeError
	for _, args := range [][]string{
		{"encrypt", "--with-key=tpm2"}, {"encrypt", "--with-key=host+tpm2"}, {"encrypt", "--with-key=bogus"},
		{"encrypt", "-T"}, {"encrypt", "--tpm2-device=auto"}, {"encrypt", "--tpm2-pcrs=7"},
		{"decrypt", "-T"}, {"decrypt", "--tpm2-device=auto"},
	} {
		if _, _, err := run(t, "x", args...); !errors.As(err, &unsup) {
			t.Errorf("%v: %v", args, err)
		}
	}
	// A credential for a TPM is reported, not guessed at.
	tpm := make([]byte, 80)
	copy(tpm, []byte{0xc7, 0x23, 0x7a, 0x80, 0x25, 0xf1, 0x4d, 0xd3, 0xad, 0xa1, 0x0f, 0xc0, 0x2f, 0x8c, 0xbc, 0xf0})
	if _, _, err := run(t, sdcreds.Armor(tpm, 79), "decrypt"); err == nil {
		t.Error("garbage accepted")
	}
	// Mutually exclusive or contradictory flags.
	for _, args := range [][]string{
		{"encrypt", "--user", "--uid=0"}, {"encrypt", "-H", "--with-key=null"}, {"encrypt", "--uid=no-such-user-xyz", "--with-key=host"},
		{"encrypt", "--uid=4294967296"},
	} {
		if _, _, err := run(t, "x", args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestInputRefusals(t *testing.T) {
	dir := env(t)
	if _, _, err := run(t, strings.Repeat("a", sdcreds.PlaintextMax+1), "encrypt", "--with-key=null"); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Errorf("1 MiB + 1: %v", err)
	}
	if _, _, err := run(t, strings.Repeat("a", sdcreds.PlaintextMax), "encrypt", "--with-key=null"); err != nil {
		t.Errorf("1 MiB: %v", err)
	}
	if _, _, err := run(t, strings.Repeat("A", sdcreds.EncryptedMax*3), "decrypt"); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Errorf("huge credential: %v", err)
	}
	if _, _, err := run(t, "", "encrypt", filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing input: %v", err)
	}
	if _, _, err := run(t, "!!not base64!!", "decrypt"); err == nil {
		t.Error("garbage accepted")
	}
	if _, _, err := run(t, "x", "encrypt", "a", "b", "c"); err == nil {
		t.Error("three arguments accepted")
	}
	// A machine id that cannot be read fails host mode, not null mode.
	t.Setenv(MachineIDEnv, filepath.Join(dir, "none"))
	if _, _, err := run(t, "x", "encrypt"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no machine id: %v", err)
	}
	if _, _, err := run(t, "x", "encrypt", "--with-key=null"); err != nil {
		t.Errorf("null mode: %v", err)
	}
	if _, _, err := run(t, "", "setup"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("setup without machine id: %v", err)
	}
}

func TestSetupNeverOverwrites(t *testing.T) {
	needHostFiles(t)
	dir := env(t)
	p := filepath.Join(dir, "weird")
	os.WriteFile(p, []byte("not a secret at all, but long enough"), 0o400)
	if _, _, err := run(t, "", "setup", "--path", p); err == nil {
		t.Error("an unusable secret was accepted")
	}
	if b, _ := os.ReadFile(p); !strings.HasPrefix(string(b), "not a secret") {
		t.Errorf("overwritten: %q", b)
	}
	t.Setenv(sdcreds.HostSecretEnv, "relative/path")
	if _, _, err := run(t, "", "setup"); !errors.Is(err, sdcreds.ErrInvalid) {
		t.Errorf("relative $%s: %v", sdcreds.HostSecretEnv, err)
	}
}

func fakeOps(calls *[]string, execErr error) func() s6.Ops {
	return func() s6.Ops {
		rec := func(n string) error { *calls = append(*calls, n); return nil }
		return s6.Ops{
			LookupUser: func(string) (s6.User, error) { rec("lookup"); return s6.User{UID: 1, GID: 1}, nil },
			Unshare:    func() error { return rec("unshare") }, MountRAM: func(string) error { return rec("mount") },
			Chown:     func(string, int, int) error { return nil },
			RemountRO: func(string) error { return rec("remount") },
			Unmount: func(d string) error {
				rec("unmount")
				ents, _ := os.ReadDir(d)
				for _, e := range ents {
					os.Remove(filepath.Join(d, e.Name()))
				}
				return nil
			},
			DropPrivileges: func(s6.User) error { return rec("drop") },
			Exec:           func(argv, env []string) error { rec("exec " + strings.Join(argv, " ")); return execErr },
		}
	}
}

func TestS6RunAndFinish(t *testing.T) {
	dir := env(t)
	src, base := filepath.Join(dir, "src"), filepath.Join(dir, "run")
	os.MkdirAll(src, 0o700)
	os.MkdirAll(base, 0o700)
	t.Setenv("SYSTEMD_CREDENTIAL_VALIDATE_NAME", "")
	enc := mustRun(t, "hunter2", "encrypt", "--with-key=null", "--name=db")
	os.WriteFile(filepath.Join(src, "db"), []byte(enc), 0o600)

	defer func(o func() s6.Ops) { s6Ops = o }(s6Ops)
	var calls []string
	boom := errors.New("exec reached")
	s6Ops = fakeOps(&calls, boom)
	// The null key is accepted or refused by the boot policy of the machine;
	// this test is about the plumbing, so the policy is not the question.
	_, _, err := run(t, "", "s6-run", "--service=web", "--user=svc", "--base-dir="+base, "--source="+src, "--unshare", "--", "/bin/web", "-v")
	if err != nil && !errors.Is(err, boom) {
		if errors.Is(err, sdcreds.ErrNullRefused) {
			t.Skipf("this machine's boot policy refuses the null key: %v", err)
		}
		t.Fatal(err)
	}
	want := "lookup unshare mount remount drop exec /bin/web -v unmount"
	if strings.Join(calls, " ") != want {
		t.Errorf("calls: %v", calls)
	}
	// A wrongly named credential fails before anything is mounted.
	os.Rename(filepath.Join(src, "db"), filepath.Join(src, "renamed"))
	calls = nil
	if _, _, err := run(t, "", "s6-run", "--service=web", "--user=svc", "--base-dir="+base, "--source="+src, "--", "/bin/web"); !errors.Is(err, sdcreds.ErrNameMismatch) {
		t.Errorf("%v", err)
	}
	if strings.Contains(strings.Join(calls, " "), "mount") {
		t.Errorf("mounted: %v", calls)
	}
	// finish
	calls = nil
	os.Mkdir(filepath.Join(base, "web"), 0o700)
	mustRun(t, "", "s6-finish", "--service=web", "--base-dir="+base)
	if strings.Join(calls, " ") != "unmount" {
		t.Errorf("%v", calls)
	}
	if _, err := os.Stat(filepath.Join(base, "web")); err == nil {
		t.Error("directory left")
	}
	// Required flags.
	for _, args := range [][]string{{"s6-run"}, {"s6-run", "--service=web", "--user=u", "--source=/x"}, {"s6-run", "--service=web", "--source=/x", "--", "c"}, {"s6-finish"}} {
		if _, _, err := run(t, "", args...); err == nil {
			t.Errorf("%v accepted", args)
		}
	}
}

func TestMainExitCode(t *testing.T) {
	var code = -1
	defer func(o func(int), a []string) { osExit, os.Args = o, a }(osExit, os.Args)
	osExit = func(c int) { code = c }
	os.Args = []string{"sdcreds", "bogus-command"}
	main()
	if code != 1 {
		t.Errorf("exit code %d", code)
	}
	code = -1
	os.Args = []string{"sdcreds", "--help"}
	main()
	if code != -1 {
		t.Errorf("--help exited with %d", code)
	}
}
