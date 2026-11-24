//go:build unix

package main

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/go-authn/sdcreds/s6"
)

// --keep-cap is repeatable and comma-separated, and has no default.
func TestS6RunKeepCapFlag(t *testing.T) {
	src, base, secret, mid := hostSealed(t)
	asOwner(t, uint32(os.Getuid()))
	withOps(t)
	oldRun := s6Run
	defer func() { s6Run = oldRun }()
	for name, tc := range map[string]struct {
		flags []string
		want  []s6.Cap
	}{
		"no default":        {nil, nil},
		"one":               {[]string{"--keep-cap=CAP_NET_ADMIN"}, []s6.Cap{s6.CapNetAdmin}},
		"repeated, comma":   {[]string{"--keep-cap=CAP_NET_RAW,CAP_NET_ADMIN", "--keep-cap", "CAP_IPC_LOCK"}, []s6.Cap{s6.CapNetAdmin, s6.CapNetRaw, s6.CapIPCLock}},
		"the same, twice":   {[]string{"--keep-cap=CAP_NET_ADMIN", "--keep-cap=CAP_NET_ADMIN"}, []s6.Cap{s6.CapNetAdmin}},
		"all seven allowed": {[]string{"--keep-cap=CAP_NET_ADMIN,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_NET_BROADCAST,CAP_IPC_LOCK,CAP_WAKE_ALARM,CAP_BLOCK_SUSPEND"}, []s6.Cap{10, 11, 12, 13, 14, 35, 36}},
	} {
		var cfg s6.Config
		called := false
		s6Run = func(c s6.Config, o s6.Ops) error { cfg, called = c, true; return nil }
		args := append([]string{"s6-run", "--service=web", "--user=svc", "--base-dir=" + base, "--source=" + src,
			"--secret=" + secret, "--machine-id-file=" + mid}, tc.flags...)
		_, _, err := run(t, "", append(args, "--", "/bin/web")...)
		if err != nil || !called || !reflect.DeepEqual(cfg.KeepCaps, tc.want) {
			t.Errorf("%s: %v called=%v KeepCaps=%v, want %v", name, err, called, cfg.KeepCaps, tc.want)
		}
	}
}

// A capability that is not allowed, or not a capability, stops s6-run before the
// key is read: the (missing) key file is never opened, nothing is run.
func TestS6RunKeepCapRefusals(t *testing.T) {
	dir := env(t)
	withOps(t)
	oldRun, oldHarden := s6Run, hardenProcess
	defer func() { s6Run, hardenProcess = oldRun, oldHarden }()
	called, hardened := false, false
	s6Run = func(c s6.Config, o s6.Ops) error { called = true; return nil }
	hardenProcess = func() { hardened = true }
	for _, flag := range []string{"CAP_SYS_ADMIN", "CAP_SETUID", "CAP_NET_ADMIN,CAP_KILL", "CAP_NOPE", "net_admin", ""} {
		called, hardened = false, false
		_, _, err := run(t, "", "s6-run", "--service=web", "--user=svc", "--base-dir="+dir, "--source="+dir,
			"--secret="+dir+"/missing.secret", "--keep-cap="+flag, "--", "/bin/web")
		if err == nil || !strings.Contains(err.Error(), "the allowlist is CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_NET_BROADCAST, CAP_IPC_LOCK, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND") {
			t.Errorf("%q: %v", flag, err)
		}
		if err != nil && strings.Contains(err.Error(), "--secret") {
			t.Errorf("%q: the key was read before the capabilities were judged: %v", flag, err)
		}
		if called || hardened {
			t.Errorf("%q: went on (run=%v, hardened=%v)", flag, called, hardened)
		}
	}
}

func TestS6RunHelpNamesKeepCap(t *testing.T) {
	out, _, err := run(t, "", "s6-run", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--keep-cap", "CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_NET_BROADCAST", "CAP_IPC_LOCK", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "no_new_privs", "NOROOT"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q missing from the help:\n%s", want, out)
		}
	}
}
