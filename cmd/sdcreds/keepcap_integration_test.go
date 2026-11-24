//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// probeRig builds the probe service into a tmpfs that allows set-user-id files
// (nosuid is not set), owned by root and executable by everyone.
func probeRig(t *testing.T) (r *itRig, bindir, probe string) {
	t.Helper()
	r = newITRig(t)
	bindir, err := os.MkdirTemp("/run", "sdcreds-it-probe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(bindir) })
	if err := os.Chmod(bindir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("probes", bindir, "tmpfs", 0, "mode=0755"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Unmount(bindir, syscall.MNT_DETACH) })
	probe = filepath.Join(bindir, "capprobe")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", probe, "./testdata/capprobe").CombinedOutput(); err != nil {
		t.Fatalf("build the probe: %v: %s", err, out)
	}
	return r, bindir, probe
}

// fields reads the "Key:\tvalue" lines of the probe, and its "key: value" ones.
func fields(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// capMask is the hex string the kernel prints for the set of capabilities.
func capMask(caps ...uint) string {
	var m uint64
	for _, c := range caps {
		m |= 1 << c
	}
	const hexd = "0123456789abcdef"
	b := []byte("0000000000000000")
	for i := 15; i >= 0; i-- {
		b[i] = hexd[m&0xf]
		m >>= 4
	}
	return string(b)
}

// The service of s6-run --keep-cap has exactly the capabilities that were
// kept, in the bounding, permitted, inheritable, effective and ambient sets
// alike, with no_new_privs on and the securebits locked; without the flag every
// set is empty, as in v0.1.0. Run it with SDCREDS_S6_INTEGRATION=1, as root,
// in the interop container started with --privileged.
func TestS6KeepCapAsRoot(t *testing.T) {
	r, _, probe := probeRig(t)
	const locked = "0x3" // NOROOT, NOROOT_LOCKED
	for name, tc := range map[string]struct {
		flags []string
		caps  []uint
	}{
		"one":               {[]string{"--keep-cap=CAP_NET_ADMIN"}, []uint{12}},
		"repeated, comma":   {[]string{"--keep-cap=CAP_NET_ADMIN", "--keep-cap=CAP_NET_RAW,CAP_IPC_LOCK"}, []uint{12, 13, 14}},
		"a high capability": {[]string{"--keep-cap=CAP_BLOCK_SUSPEND,CAP_WAKE_ALARM"}, []uint{35, 36}},
		"all seven": {[]string{"--keep-cap=CAP_NET_ADMIN,CAP_NET_BIND_SERVICE,CAP_NET_RAW,CAP_NET_BROADCAST,CAP_IPC_LOCK,CAP_WAKE_ALARM,CAP_BLOCK_SUSPEND"},
			[]uint{10, 11, 12, 13, 14, 35, 36}},
	} {
		for _, unshare := range []bool{true, false} {
			args := r.runArgs(unshare, probe)
			args = append(args[:1], append(tc.flags, args[1:]...)...)
			out, err := r.sdcreds("", args...)
			if err != nil {
				t.Fatalf("%s: %v: %s", name, err, out)
			}
			got := fields(out)
			want := capMask(tc.caps...)
			t.Logf("%s unshare=%v: CapEff=%s CapPrm=%s CapInh=%s CapBnd=%s CapAmb=%s securebits=%s", name, unshare,
				got["CapEff"], got["CapPrm"], got["CapInh"], got["CapBnd"], got["CapAmb"], got["securebits"])
			for _, k := range []string{"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"} {
				if got[k] != want {
					t.Errorf("%s: %s is %s, want exactly %s", name, k, got[k], want)
				}
			}
			if got["NoNewPrivs"] != "1" {
				t.Errorf("%s: NoNewPrivs %q", name, got["NoNewPrivs"])
			}
			if !strings.HasPrefix(got["securebits"], locked+" ") {
				t.Errorf("%s: securebits %q, want %s: NOROOT, locked", name, got["securebits"], locked)
			}
			// The service is still the service user, and cannot undo any of it.
			if got["Uid"] != "1000\t1000\t1000\t1000" || got["Gid"] != "1000\t1000\t1000\t1000" {
				t.Errorf("%s: ids %q %q", name, got["Uid"], got["Gid"])
			}
			for k, want := range map[string]string{
				"clear securebits":    "operation not permitted",
				"setuid 0":            "operation not permitted",
				"raise CAP_SYS_ADMIN": "operation not permitted",
			} {
				if got[k] != want {
					t.Errorf("%s: %s: %q, want %q", name, k, got[k], want)
				}
			}
			if r.mounted() {
				t.Errorf("%s: still mounted after the service ended", name)
			}
		}
	}
}

// Negative control: without --keep-cap every set is empty, and no securebit
// is set: exactly what v0.1.0 gave.
func TestS6WithoutKeepCapEverySetIsEmpty(t *testing.T) {
	r, _, probe := probeRig(t)
	out, err := r.sdcreds("", r.runArgs(true, probe)...)
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	got := fields(out)
	zero := capMask()
	for _, k := range []string{"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"} {
		if got[k] != zero {
			t.Errorf("%s is %s, want %s", k, got[k], zero)
		}
	}
	if got["NoNewPrivs"] != "1" || !strings.HasPrefix(got["securebits"], "0x0 ") {
		t.Errorf("NoNewPrivs %q, securebits %q", got["NoNewPrivs"], got["securebits"])
	}
}

// A forbidden or unknown capability is refused before anything is decrypted or
// mounted, with the allowlist in the message.
func TestS6KeepCapRefusedBeforeAnythingIsMounted(t *testing.T) {
	r, _, probe := probeRig(t)
	for _, flag := range []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN,CAP_DAC_OVERRIDE", "CAP_NOT_A_CAP"} {
		args := r.runArgs(true, probe)
		args = append(args[:1], append([]string{"--keep-cap=" + flag}, args[1:]...)...)
		out, err := r.sdcreds("", args...)
		if err == nil || !strings.Contains(out, "the allowlist is CAP_NET_ADMIN") {
			t.Errorf("%s: %v: %s", flag, err, out)
		}
		if r.mounted() {
			t.Errorf("%s: mounted", flag)
		}
		if _, err := os.Stat(filepath.Join(r.base, "web")); err == nil {
			t.Errorf("%s: the credential directory was made", flag)
		}
	}
}

// s6-run itself keeps its privileges: only the service is restricted.
func TestS6KeepCapLeavesTheParentAlone(t *testing.T) {
	r, _, probe := probeRig(t)
	self := fields(mustRead(t, "/proc/self/status"))
	args := r.runArgs(false, probe, "hold")
	args = append(args[:1], append([]string{"--keep-cap=CAP_NET_ADMIN"}, args[1:]...)...)
	cmd := r.command("", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	sc := bufio.NewScanner(stdout)
	ready := false
	for sc.Scan() {
		if sc.Text() == "ready" {
			ready = true
			break
		}
	}
	if !ready {
		t.Fatal("the service did not start")
	}
	parent := fields(mustRead(t, "/proc/"+strconv.Itoa(cmd.Process.Pid)+"/status"))
	for _, k := range []string{"CapEff", "CapPrm", "CapBnd"} {
		if parent[k] != self[k] {
			t.Errorf("s6-run's %s is %s, the root test process has %s", k, parent[k], self[k])
		}
	}
	if parent["NoNewPrivs"] != "0" || parent["Uid"] != "0\t0\t0\t0" {
		t.Errorf("s6-run: NoNewPrivs %q, Uid %q", parent["NoNewPrivs"], parent["Uid"])
	}
}

// no_new_privs: an exec of a set-user-id-root file or of a file with file
// capabilities gains nothing, with the flag and without it. (A file capability
// outside the bounding set is already refused by the bounding set; NET_RAW and
// SYS_ADMIN, which the service did not keep, are in the file here, and
// NET_ADMIN, which it did, must not be raised in any set it was not in.)
func TestS6KeepCapExecOfPrivilegedFilesGainsNothing(t *testing.T) {
	r, bindir, probe := probeRig(t)
	body, err := os.ReadFile(probe)
	if err != nil {
		t.Fatal(err)
	}
	suid := filepath.Join(bindir, "suid-root")
	if err := os.WriteFile(suid, body, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suid, 0o755|os.ModeSetuid); err != nil { // chown is root's already
		t.Fatal(err)
	}
	if st, _ := os.Stat(suid); st.Mode()&os.ModeSetuid == 0 {
		t.Fatal("the control file is not set-user-id")
	}
	// security.capability, VFS_CAP_REVISION_2 (linux/capability.h): magic_etc
	// (with the effective flag or without), then permitted and inheritable of
	// caps 0-31 and 32-63.
	fileCap := func(name string, flags, perm uint32) string {
		p := filepath.Join(bindir, name)
		if err := os.WriteFile(p, body, 0o755); err != nil {
			t.Fatal(err)
		}
		xattr := make([]byte, 20)
		binary.LittleEndian.PutUint32(xattr[0:], 0x02000000|flags)
		binary.LittleEndian.PutUint32(xattr[4:], perm)
		binary.LittleEndian.PutUint32(xattr[8:], perm)
		if err := syscall.Setxattr(p, "security.capability", xattr, 0); err != nil {
			t.Fatalf("setting a file capability: %v", err)
		}
		return p
	}
	// NET_ADMIN, NET_RAW and SYS_ADMIN, effective: a file the kernel refuses to
	// run when its permitted set cannot be had. Then NET_ADMIN and NET_RAW, not
	// effective: a file that runs.
	refused := fileCap("filecap-effective", 1, 1<<12|1<<13|1<<21)
	plain := fileCap("filecap-plain", 0, 1<<12|1<<13)

	for _, flags := range [][]string{nil, {"--keep-cap=CAP_NET_ADMIN"}} {
		kept := capMask()
		if len(flags) > 0 {
			kept = capMask(12)
		}
		for name, file := range map[string]string{"set-user-id root": suid, "file capabilities, effective": refused, "file capabilities": plain} {
			args := r.runArgs(true, file)
			args = append(args[:1], append(flags, args[1:]...)...)
			out, err := r.sdcreds("", args...)
			if err != nil {
				// A refused exec gains nothing either, and leaves nothing mounted.
				if file == refused && strings.Contains(out, "operation not permitted") && !r.mounted() {
					continue
				}
				t.Fatalf("%s %v: %v: %s", name, flags, err, out)
			}
			if file == refused {
				t.Errorf("%s %v: ran: %s", name, flags, out)
			}
			got := fields(out)
			if got["Uid"] != "1000\t1000\t1000\t1000" {
				t.Errorf("%s %v: gained a uid: %q", name, flags, got["Uid"])
			}
			for _, k := range []string{"CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"} {
				// Nothing beyond the kept set in any of them; the file with no
				// file capabilities keeps exactly the set.
				if !subset(t, got[k], kept) || (file == suid && got[k] != kept) {
					t.Errorf("%s %v: %s is %s, the kept set is %s", name, flags, k, got[k], kept)
				}
			}
			if got["NoNewPrivs"] != "1" {
				t.Errorf("%s %v: no_new_privs %q", name, flags, got["NoNewPrivs"])
			}
		}
	}
}

// subset reports whether every capability of the set a is in the set b (both as
// the kernel prints them).
func subset(t *testing.T, a, b string) bool {
	t.Helper()
	x, err1 := strconv.ParseUint(a, 16, 64)
	y, err2 := strconv.ParseUint(b, 16, 64)
	if err1 != nil || err2 != nil {
		t.Fatalf("not capability sets: %q %q", a, b)
	}
	return x&^y == 0
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
