//go:build unix

package main

import (
	"bytes"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/cobra"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/delivery"
)

// runEnv replaces every seam of `run` and returns what the flow saw. The
// passwd database is a table, the caller is root, the flow is a spy.
type runEnv struct {
	flows int
	exit  int
	dir   string
	prog  string
}

func newRunEnv(t *testing.T, os_ string) *runEnv {
	t.Helper()
	e := &runEnv{exit: -1, dir: t.TempDir()}
	oldGoos, oldEuid, oldLook, oldGroups, oldFlow, oldExit, oldConf := goos, euid, lookupUser, userGroupIDs, runFlow, osExit, loginConfPath
	t.Cleanup(func() {
		goos, euid, lookupUser, userGroupIDs, runFlow, osExit, loginConfPath = oldGoos, oldEuid, oldLook, oldGroups, oldFlow, oldExit, oldConf
	})
	goos = os_
	euid = func() int { return 0 }
	lookupUser = func(name string) (*user.User, error) {
		switch name {
		case "svc":
			return &user.User{Username: "svc", Uid: "12345", Gid: "12345"}, nil
		case "toor":
			return &user.User{Username: "toor", Uid: "0", Gid: "0"}, nil
		case "wrap":
			return &user.User{Username: "wrap", Uid: "4294967296", Gid: "12345"}, nil
		case "wrapgid":
			return &user.User{Username: "wrapgid", Uid: "12345", Gid: "4294967296"}, nil
		case "gid0":
			return &user.User{Username: "gid0", Uid: "12345", Gid: "0"}, nil
		case "weird":
			return &user.User{Username: "weird", Uid: "x", Gid: "y"}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	userGroupIDs = func(u *user.User) ([]string, error) { return []string{u.Gid, "77"}, nil }
	runFlow = func(*cobra.Command, *runPlan) error { e.flows++; return nil }
	osExit = func(c int) { e.exit = c }
	loginConfPath = filepath.Join(e.dir, "login.conf")
	if err := os.WriteFile(loginConfPath, []byte("# c\ndefault:\\\n\t:x=y:\nstaff:\\\n\t:z=1:\ndaemon|svc class:\\\n\t:w=2:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A program the target (uid 12345) can execute: world-searchable parents.
	e.prog = filepath.Join(e.dir, "bin", "prog")
	if err := os.Mkdir(filepath.Dir(e.prog), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.prog, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.dir, 0o755); err != nil {
		t.Fatal(err)
	}
	oldFrom := execAncestorsFrom
	t.Cleanup(func() { execAncestorsFrom = oldFrom })
	execAncestorsFrom, _ = filepath.EvalSymlinks(e.dir)
	oldTU, oldAF := trustedUID, ancestorsFrom
	t.Cleanup(func() { trustedUID, ancestorsFrom = oldTU, oldAF })
	trustedUID, ancestorsFrom = uint32(os.Getuid()), execAncestorsFrom
	if err := os.Mkdir(filepath.Join(e.dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *runEnv) src() string { return filepath.Join(e.dir, "src") }

// base returns the flags every case shares, then the case's extra arguments.
func (e *runEnv) args(extra ...string) []string {
	a := []string{"run", "--service=web", "--user=svc", "--source=" + e.src()}
	return append(a, extra...)
}

// Every refusal: the typed error from plan, exit status 2 from the command, no
// flow (so no key is opened, nothing decrypted or mounted).
var errGroups = errors.New("groups unreadable")

// The class check says WHY it refused: an unreadable or oversized login.conf
// is not the same refusal as an unknown class.
func TestCheckClassSaysWhy(t *testing.T) {
	e := newRunEnv(t, "openbsd")
	loginConfPath = filepath.Join(e.dir, "absent")
	if err := checkClass("staff"); err == nil || !errors.Is(err, errBadClass) || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("missing login.conf: %v", err)
	}
	loginConfPath = filepath.Join(e.dir, "big")
	big := append([]byte("staff:\\\n\t:x=y:\n"), bytes.Repeat([]byte("# pad\n"), loginConfMax/6+1)...)
	if err := os.WriteFile(loginConfPath, big, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkClass("staff"); err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("oversized login.conf: %v", err)
	}
}

func TestRunRefusals(t *testing.T) {
	big := make([]byte, 2<<20)
	cases := []struct {
		name  string
		goos  string
		setup func(e *runEnv)
		flags func(e *runEnv) []string // after "run ..." ; includes -- PROGRAM
		want  error
	}{
		{"no program", "openbsd", nil, func(e *runEnv) []string { return nil }, errNoProgram},
		{"relative program", "openbsd", nil, func(e *runEnv) []string { return []string{"--", "prog"} }, errProgramNotAbs},
		{"unnormalised program", "openbsd", nil, func(e *runEnv) []string { return []string{"--", e.dir + "/bin/../bin/prog"} }, errProgramNotAbs},
		{"bad service", "openbsd", nil, func(e *runEnv) []string { return []string{"--service=.web", "--", e.prog} }, delivery.ErrBadService},
		{"upper case service", "openbsd", nil, func(e *runEnv) []string { return []string{"--service=Web", "--", e.prog} }, delivery.ErrBadService},
		{"unknown user", "openbsd", nil, func(e *runEnv) []string { return []string{"--user=nobody-here", "--", e.prog} }, errUnknownUser},
		{"user without numeric id", "openbsd", nil, func(e *runEnv) []string { return []string{"--user=weird", "--", e.prog} }, errUnknownUser},
		{"uid 0", "openbsd", nil, func(e *runEnv) []string { return []string{"--user=toor", "--", e.prog} }, delivery.ErrRootTarget},
		{"uid that wraps to 0", "openbsd", nil, func(e *runEnv) []string { return []string{"--user=wrap", "--", e.prog} }, delivery.ErrBadID},
		{"gid that wraps to 0", "openbsd", nil, func(e *runEnv) []string { return []string{"--user=wrapgid", "--", e.prog} }, delivery.ErrBadID},
		{"gid 0", "openbsd", nil, func(e *runEnv) []string { return []string{"--user=gid0", "--", e.prog} }, delivery.ErrRootTarget},
		{"supplementary group 0", "openbsd",
			func(e *runEnv) {
				userGroupIDs = func(u *user.User) ([]string, error) { return []string{u.Gid, "0"}, nil }
			},
			func(e *runEnv) []string { return []string{"--", e.prog} }, delivery.ErrRootTarget},
		{"supplementary group that wraps", "openbsd",
			func(e *runEnv) {
				userGroupIDs = func(u *user.User) ([]string, error) { return []string{u.Gid, "4294967296"}, nil }
			},
			func(e *runEnv) []string { return []string{"--", e.prog} }, delivery.ErrBadID},
		{"unknown class", "openbsd", nil, func(e *runEnv) []string { return []string{"--class=nope", "--", e.prog} }, errBadClass},
		{"login.conf missing", "openbsd", func(e *runEnv) { loginConfPath = filepath.Join(e.dir, "absent") },
			func(e *runEnv) []string { return []string{"--class=staff", "--", e.prog} }, errBadClass},
		{"uid 0 is refused before the groups are read", "openbsd",
			func(e *runEnv) { userGroupIDs = func(*user.User) ([]string, error) { return nil, errors.New("boom") } },
			func(e *runEnv) []string { return []string{"--user=toor", "--", e.prog} }, delivery.ErrRootTarget},
		{"groups unreadable", "openbsd",
			func(e *runEnv) { userGroupIDs = func(*user.User) ([]string, error) { return nil, errGroups } },
			func(e *runEnv) []string { return []string{"--", e.prog} }, errGroups},
		{"keep-cap on openbsd", "openbsd", nil, func(e *runEnv) []string { return []string{"--keep-cap=CAP_NET_RAW", "--", e.prog} }, errKeepCapOS},
		{"class on linux", "linux", nil, func(e *runEnv) []string { return []string{"--class=staff", "--", e.prog} }, errClassOS},
		{"bad capability", "linux", nil, func(e *runEnv) []string { return []string{"--keep-cap=CAP_SYS_ADMIN", "--", e.prog} }, nil},
		{"not root", "openbsd", func(e *runEnv) { euid = func() int { return 1000 } },
			func(e *runEnv) []string { return []string{"--", e.prog} }, delivery.ErrNotRoot},
		{"program not executable", "openbsd", func(e *runEnv) { _ = os.Chmod(e.prog, 0o700) },
			func(e *runEnv) []string { return []string{"--", e.prog} }, errNotExecutable},
		{"program directory not searchable", "openbsd", func(e *runEnv) { _ = os.Chmod(filepath.Dir(e.prog), 0o700) },
			func(e *runEnv) []string { return []string{"--", e.prog} }, errNotExecutable},
		{"program missing", "openbsd", nil, func(e *runEnv) []string { return []string{"--", e.dir + "/bin/none"} }, errNotExecutable},
		{"too many entries", "openbsd", func(e *runEnv) {
			for i := 0; i <= delivery.MaxEntries; i++ {
				if err := os.WriteFile(filepath.Join(e.src(), "c"+strconv.Itoa(i)), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}, func(e *runEnv) []string { return []string{"--", e.prog} }, delivery.ErrTooManyEntry},
		{"sealed too large", "openbsd", func(e *runEnv) { _ = os.WriteFile(filepath.Join(e.src(), "big"), big, 0o600) },
			func(e *runEnv) []string { return []string{"--", e.prog} }, sdcreds.ErrTooLarge},
		{"invalid credential name", "openbsd", func(e *runEnv) { _ = os.WriteFile(filepath.Join(e.src(), "a:b"), nil, 0o600) },
			func(e *runEnv) []string { return []string{"--", e.prog} }, delivery.ErrBadName},
		{"source symlink", "openbsd", func(e *runEnv) { _ = os.Symlink("/etc/passwd", filepath.Join(e.src(), "l")) },
			func(e *runEnv) []string { return []string{"--", e.prog} }, nil},
		{"source fifo", "openbsd", func(e *runEnv) { _ = syscall.Mkfifo(filepath.Join(e.src(), "f"), 0o600) },
			func(e *runEnv) []string { return []string{"--", e.prog} }, nil},
		{"source missing", "openbsd", nil, func(e *runEnv) []string { return []string{"--source=" + e.dir + "/none", "--", e.prog} }, nil},
		{"base not absolute", "openbsd", nil, func(e *runEnv) []string { return []string{"--base=rel", "--", e.prog} }, delivery.ErrBadBase},
		{"base is /", "openbsd", nil, func(e *runEnv) []string { return []string{"--base=/", "--", e.prog} }, delivery.ErrBadBase},
		{"missing --user", "openbsd", nil, func(e *runEnv) []string { return []string{"--user=", "--", e.prog} }, errMissingFlag},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newRunEnv(t, c.goos)
			if c.setup != nil {
				c.setup(e)
			}
			extra := c.flags(e)
			args := append(e.args(), extra...)
			f, pargs := splitFlags(t, args)
			_, err := plan(f, pargs)
			var r *refusal
			if !errors.As(err, &r) {
				t.Fatalf("plan: %v, want a refusal", err)
			}
			if c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("plan: %v, want %v", err, c.want)
			}
			_, se, _ := run(t, "", args...)
			if e.exit != exitRefused || e.flows != 0 {
				t.Errorf("exit %d, flows %d, stderr %q; want exit 2 and no flow", e.exit, e.flows, se)
			}
			if !strings.Contains(se, "refused") {
				t.Errorf("stderr %q does not say it refused", se)
			}
		})
	}
}

// splitFlags runs the flag parser of `run` on args, so that plan sees what the
// command does.
func splitFlags(t *testing.T, args []string) (runFlags, []string) {
	t.Helper()
	var got runFlags
	var rest []string
	cmd := runCmd()
	cmd.RunE = nil
	cmd.Run = func(c *cobra.Command, a []string) { rest = a }
	cmd.SetArgs(args[1:])
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	fl := cmd.Flags()
	got.service, _ = fl.GetString("service")
	got.user, _ = fl.GetString("user")
	got.source, _ = fl.GetString("source")
	got.class, _ = fl.GetString("class")
	got.base, _ = fl.GetString("base")
	got.keepCap, _ = fl.GetStringArray("keep-cap")
	return got, rest
}

func TestRunAcceptsAndChecks(t *testing.T) {
	e := newRunEnv(t, "openbsd")
	if err := os.WriteFile(filepath.Join(e.src(), "smtp-password"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	so, _, err := run(t, "", append(e.args("--class=daemon"), "--", e.prog, "--flag", "arg")...)
	if err != nil || e.flows != 1 || e.exit != -1 {
		t.Fatalf("err %v flows %d exit %d (%q)", err, e.flows, e.exit, so)
	}
	// --check runs the refusals and stops there.
	e.flows = 0
	so, _, err = run(t, "", append(e.args("--check"), "--", e.prog)...)
	if err != nil || e.flows != 0 || strings.TrimSpace(so) != "ok" {
		t.Fatalf("check: err %v flows %d out %q", err, e.flows, so)
	}
	// the plan carries what the flow needs.
	f, pargs := splitFlags(t, append(e.args(), "--", e.prog, "--flag", "arg"))
	p, err := plan(f, pargs)
	if err != nil {
		t.Fatal(err)
	}
	if p.uid != 12345 || p.gid != 12345 || len(p.groups) != 2 || p.program != e.prog || strings.Join(p.args, " ") != "--flag arg" ||
		len(p.creds) != 1 || p.creds[0].Name != "smtp-password" || p.base != delivery.DefaultBase {
		t.Errorf("%+v", p)
	}
	// Linux takes the default base of s6 and accepts the capability list.
	e = newRunEnv(t, "linux")
	f, pargs = splitFlags(t, append(e.args("--keep-cap=CAP_NET_RAW"), "--", e.prog))
	if p, err = plan(f, pargs); err != nil || p.base != "/run/sdcreds" || len(p.keep) != 1 {
		t.Errorf("linux: %v %+v", err, p)
	}
}

// Without a flow for the platform the command refuses instead of doing nothing.
func TestRunWithoutFlow(t *testing.T) {
	e := newRunEnv(t, "openbsd")
	runFlow = nil
	_, se, _ := run(t, "", append(e.args(), "--", e.prog)...)
	if e.exit != exitRefused || !strings.Contains(se, "not supported") {
		t.Errorf("exit %d %q", e.exit, se)
	}
}

// A failure of the flow that is not a refusal passes through as an error.
func TestRunFlowErrorIsNotARefusal(t *testing.T) {
	e := newRunEnv(t, "openbsd")
	boom := errors.New("boom")
	runFlow = func(*cobra.Command, *runPlan) error { return boom }
	_, _, err := run(t, "", append(e.args(), "--", e.prog)...)
	if !errors.Is(err, boom) || e.exit != -1 {
		t.Errorf("err %v exit %d", err, e.exit)
	}
}

func TestCanExecAs(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	me := os.Getuid()
	oldFrom := execAncestorsFrom
	t.Cleanup(func() { execAncestorsFrom = oldFrom })
	execAncestorsFrom, _ = filepath.EvalSymlinks(dir)
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, nil, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	st, _ := os.Stat(mk("probe", 0o600))
	gid := int(st.Sys().(*syscall.Stat_t).Gid)
	other := me + 1000
	for _, c := range []struct {
		name   string
		mode   os.FileMode
		uid    int
		groups []int
		ok     bool
	}{
		{"owner x", 0o100, me, nil, true},
		{"owner no x but others x", 0o001, me, nil, false}, // the owner class decides
		{"group x", 0o010, other, []int{gid}, true},
		{"group no x others x", 0o001, other, []int{gid}, false},
		{"others x", 0o001, other, nil, true},
		{"others none", 0o770, other, nil, false},
		{"no bit", 0o600, other, nil, false},
	} {
		p := mk(strings.ReplaceAll(c.name, " ", "_"), c.mode)
		err := canExecAs(p, c.uid, other+1, c.groups)
		if c.ok != (err == nil) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// a directory is not a program; a link is resolved; a dead link fails.
	d755 := filepath.Join(dir, "d755")
	if err := os.Mkdir(d755, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := canExecAs(d755, other, other, nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory: %v", err)
	}
	good := mk("good", 0o755)
	ln := filepath.Join(dir, "ln")
	if err := os.Symlink(good, ln); err != nil {
		t.Fatal(err)
	}
	if err := canExecAs(ln, other, other, nil); err != nil {
		t.Errorf("link: %v", err)
	}
	if err := os.Symlink(filepath.Join(dir, "gone"), filepath.Join(dir, "dead")); err != nil {
		t.Fatal(err)
	}
	if err := canExecAs(filepath.Join(dir, "dead"), other, other, nil); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Errorf("a dead link: %v", err)
	}
	// a path that does not exist (relative, so the walk must still end).
	if err := canExecAs("nowhere/prog", other, other, nil); err == nil || !strings.Contains(err.Error(), "nowhere") {
		t.Errorf("a relative missing path: %v", err)
	}
	// a stat that fails after the path was resolved, on a directory and on the file.
	boom := errors.New("stat boom")
	rdir, _ := filepath.EvalSymlinks(dir)
	for _, failOn := range []string{rdir, filepath.Join(rdir, "good")} {
		statPath = func(p string) (os.FileInfo, error) {
			if p == failOn {
				return nil, boom
			}
			return os.Stat(p)
		}
		if err := canExecAs(good, me, other, nil); !errors.Is(err, boom) {
			t.Errorf("stat of %s failing: %v", failOn, err)
		}
	}
	statPath = os.Stat
	// an unsearchable directory in the path.
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(sub, "p")
	if err := os.WriteFile(inner, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := canExecAs(inner, other, other, nil); err == nil || !strings.Contains(err.Error(), "searchable") {
		t.Errorf("unsearchable directory: %v", err)
	}
	if err := canExecAs(inner, me, other, nil); err != nil {
		t.Errorf("owner of the directory: %v", err)
	}
}

func TestModeAllowsWithoutStat(t *testing.T) {
	if modeAllows(fakeInfo{}, 1, 0, 0, nil) {
		t.Error("a FileInfo without a stat was allowed")
	}
}

type fakeInfo struct{ os.FileInfo }

func (fakeInfo) Mode() os.FileMode { return 0o777 }
func (fakeInfo) Sys() any          { return nil }

func TestParseLoginClasses(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"", ""},
		{"# comment\n", ""},
		{"default:\\\n\t:a=b:\n", "default"},
		{"daemon|svc|a long description:\\\n\t:a=b:\nstaff:\\\n\t:c=d:\n", "daemon svc a long description staff"},
		{"  indented:\n", ""},
		{"a:\\\nb:\\\n\t:x:\nc:\n", "a c"}, // b: is a continuation, not an entry
		{"nocolon\n", "nocolon"},
		{"x\\\ny:\n", "x"},
	} {
		got, err := ParseLoginClasses(strings.NewReader(c.in))
		if err != nil || strings.Join(got, " ") != c.want {
			t.Errorf("%q: %q %v, want %q", c.in, got, err, c.want)
		}
	}
	if _, err := ParseLoginClasses(strings.NewReader(strings.Repeat("a", loginConfMax+1))); err == nil {
		t.Error("an input over the bound was read")
	}
	if _, err := ParseLoginClasses(errReader{}); err == nil {
		t.Error("a read error was lost")
	}
	// a single line longer than the buffer is not a crash.
	if _, err := ParseLoginClasses(strings.NewReader(strings.Repeat("a", loginConfMax))); err != nil {
		t.Errorf("a line at the bound: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("disk") }

func FuzzParseLoginClasses(f *testing.F) {
	for _, s := range []string{"", "default:\\\n\t:a=b:\n", "a|b:\\\n\\\n", "\\", "#\n:\n|\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		names, err := ParseLoginClasses(strings.NewReader(in))
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			if n == "" || n != strings.TrimSpace(n) || strings.ContainsAny(n, "|:\n") {
				t.Fatalf("name %q from %q", n, in)
			}
		}
	})
}

func TestParseUUID(t *testing.T) {
	good, err := parseUUID("3a2b1c6f-4e9d-574a-8c1b-2e5d7f90a1b3\n")
	if err != nil || good[0] != 0x3a || good[15] != 0xb3 {
		t.Fatalf("%x %v", good, err)
	}
	for _, s := range []string{
		"", "00000000-0000-0000-0000-000000000000", "3a2b1c6f4e9d574a8c1b2e5d7f90a1b3",
		"3a2b1c6f-4e9d-574a-8c1b-2e5d7f90a1b", "3a2b1c6f-4e9d-574a-8c1b-2e5d7f90a1bz",
		"3a2b1c6f_4e9d-574a-8c1b-2e5d7f90a1b3", "3a2b1c6f-4e9d_574a-8c1b-2e5d7f90a1b3",
		"3a2b1c6f-4e9d-574a_8c1b-2e5d7f90a1b3", "3a2b1c6f-4e9d-574a-8c1b_2e5d7f90a1b3",
	} {
		if _, err := parseUUID(s); !errors.Is(err, sdcreds.ErrInvalid) {
			t.Errorf("%q: %v", s, err)
		}
	}
}

func FuzzParseUUID(f *testing.F) {
	f.Add("3a2b1c6f-4e9d-574a-8c1b-2e5d7f90a1b3")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		id, err := parseUUID(s)
		if err == nil && id == ([16]byte{}) {
			t.Fatalf("%q accepted as null", s)
		}
	})
}

func TestEnvWithout(t *testing.T) {
	got := envWithout([]string{"A=1", "CREDENTIALS_DIRECTORY=/x", "CREDENTIALS_DIRECTORY_EXTRA=2", "B="}, "CREDENTIALS_DIRECTORY")
	if strings.Join(got, ",") != "A=1,CREDENTIALS_DIRECTORY_EXTRA=2,B=" {
		t.Errorf("%q", got)
	}
}

// The exec stub runs the program only after the go byte; EOF or anything else
// exits without running it.
func TestExecGate(t *testing.T) {
	oldExec, oldGate := execProgram, gateFile
	t.Cleanup(func() { execProgram, gateFile = oldExec, oldGate })
	var ran []string
	execProgram = func(p string, argv []string, env []string) error {
		ran = append([]string{p}, argv...)
		return errors.New("exec seam")
	}
	withGate := func(feed func(w *os.File)) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		gateFile = func() *os.File { return r }
		feed(w)
	}
	// go byte
	ran = nil
	withGate(func(w *os.File) { w.Write([]byte{goByte}); w.Close() })
	if err := execGate([]string{"--", "/bin/p", "a", "b"}); err == nil || !strings.Contains(err.Error(), "exec seam") ||
		strings.Join(ran, " ") != "/bin/p /bin/p a b" {
		t.Errorf("go: %v %q", err, ran)
	}
	// EOF: the owner died.
	ran = nil
	withGate(func(w *os.File) { w.Close() })
	if err := execGate([]string{"--", "/bin/p"}); !errors.Is(err, errGateClosed) || ran != nil {
		t.Errorf("eof: %v %q", err, ran)
	}
	// any other byte.
	withGate(func(w *os.File) { w.Write([]byte{'x'}); w.Close() })
	if err := execGate([]string{"--", "/bin/p"}); !errors.Is(err, errGateClosed) || ran != nil {
		t.Errorf("wrong byte: %v %q", err, ran)
	}
	// usage.
	for _, a := range [][]string{nil, {"--"}, {"x", "/bin/p"}} {
		if err := execGate(a); err == nil || ran != nil {
			t.Errorf("%q: %v", a, err)
		}
	}
}

func TestHelperCommandsAreHidden(t *testing.T) {
	root := RootCmd()
	for _, n := range []string{stubCommand, delivery.HelperCommand} {
		c, _, err := root.Find([]string{n})
		if err != nil || c.Name() != n || !c.Hidden || !c.DisableFlagParsing {
			t.Errorf("%s: %v %+v", n, err, c)
		}
	}
	// the helper command refuses on a system without the kernel feature, and
	// an exec stub with no program refuses.
	if _, _, err := run(t, "", stubCommand); err == nil {
		t.Error("stub without program accepted")
	}
}
