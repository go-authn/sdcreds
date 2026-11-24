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

// signalRig replaces the signal registration of Run: the channel it registers
// is kept, so that a test delivers a signal at an exact point, with no process
// signal and no timing involved. "release" is recorded in r.calls.
func signalRig(t *testing.T, r *rig) (deliver func(...syscall.Signal)) {
	t.Helper()
	var ch chan<- os.Signal
	oldN, oldS := notifySignals, stopSignals
	t.Cleanup(func() { notifySignals, stopSignals = oldN, oldS })
	notifySignals = func(c chan<- os.Signal, _ ...os.Signal) { ch = c }
	stopSignals = func(chan<- os.Signal) { r.calls = append(r.calls, "release") }
	return func(sigs ...syscall.Signal) {
		for _, s := range sigs {
			ch <- s
		}
	}
}

func noStageLeft(t *testing.T, base string) {
	t.Helper()
	ents, _ := os.ReadDir(base)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".stage-") {
			t.Errorf("%s left behind", e.Name())
		}
	}
}

// A TERM that arrives while the credentials are being staged (before, during,
// or after the mount) takes the staging mount away, starts no service, and is
// answered by the status of a process killed by it, once the clean-up is done.
func TestSignalWhileStagingTakesTheStageAway(t *testing.T) {
	points := []struct {
		name    string
		arm     func(o *Ops, deliver func(...syscall.Signal))
		mounted bool // the mount was made before the signal was seen
	}{
		{"before the stage directory", nil, false},
		{"mount", func(o *Ops, d func(...syscall.Signal)) {
			f := o.MountRAM
			o.MountRAM = func(dir string) error { d(syscall.SIGTERM); return f(dir) }
		}, true},
		{"chown", func(o *Ops, d func(...syscall.Signal)) {
			f := o.Chown
			o.Chown = func(p string, u, g int) error { d(syscall.SIGTERM); return f(p, u, g) }
		}, true},
		{"remount", func(o *Ops, d func(...syscall.Signal)) {
			f := o.RemountRO
			o.RemountRO = func(dir string) error { d(syscall.SIGTERM); return f(dir) }
		}, true},
		{"move", func(o *Ops, d func(...syscall.Signal)) {
			f := o.Move
			o.Move = func(a, b string) error { d(syscall.SIGTERM); return f(a, b) }
		}, true},
	}
	for _, p := range points {
		t.Run(p.name, func(t *testing.T) {
			r, c := newRig(t), config(t)
			deliver := signalRig(t, r)
			o := r.ops()
			started := false
			o.Start = func(User, []string, []string) (func() (int, error), error) {
				started = true
				return func() (int, error) { return 0, nil }, nil
			}
			if p.arm == nil {
				// the signal comes with the directory of the stage
				old := mkdirTemp
				defer func() { mkdirTemp = old }()
				mkdirTemp = func(dir, pat string) (string, error) { deliver(syscall.SIGTERM); return old(dir, pat) }
			} else {
				p.arm(&o, deliver)
			}
			err := Run(c, o)
			var ee *ExitError
			if !errors.As(err, &ee) || ee.Code != 128+int(syscall.SIGTERM) {
				t.Fatalf("%v", err)
			}
			if started {
				t.Error("the service was started")
			}
			if got := slices.Contains(r.calls, "mount"); got != p.mounted {
				t.Errorf("mounted=%v want %v: %v", got, p.mounted, r.calls)
			}
			for dir, n := range r.layers {
				if n != 0 {
					t.Errorf("%s still mounted (%d)", dir, n)
				}
			}
			noStageLeft(t, c.BaseDir)
			if _, err := os.Lstat(Dir(c.BaseDir, "web")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the credential directory is left: %v", err)
			}
			// the signals are released after the last unmount, not before
			last := slices.Index(r.calls, "release")
			if last != len(r.calls)-1 || slices.Index(r.calls, "unmount") > last {
				t.Errorf("signals released before the clean-up was over: %v", r.calls)
			}
		})
	}
}

// Only a signal that would have ended the process counts, and the first of
// them gives the status: SIGCONT is ignored by default, and a later signal does
// not replace an earlier one.
func TestSignalStatusIsTheFirstFatalSignal(t *testing.T) {
	for name, tc := range map[string]struct {
		sigs []syscall.Signal
		want int // 0: the service runs
	}{
		"none":            {nil, 0},
		"only CONT":       {[]syscall.Signal{syscall.SIGCONT, syscall.SIGCONT}, 0},
		"INT":             {[]syscall.Signal{syscall.SIGINT}, 128 + int(syscall.SIGINT)},
		"CONT, INT, TERM": {[]syscall.Signal{syscall.SIGCONT, syscall.SIGINT, syscall.SIGTERM}, 128 + int(syscall.SIGINT)},
		"TERM, INT":       {[]syscall.Signal{syscall.SIGTERM, syscall.SIGINT}, 128 + int(syscall.SIGTERM)},
	} {
		t.Run(name, func(t *testing.T) {
			r, c := newRig(t), config(t)
			deliver := signalRig(t, r)
			o := r.ops()
			mount := o.MountRAM
			o.MountRAM = func(dir string) error { deliver(tc.sigs...); return mount(dir) }
			err := Run(c, o)
			var ee *ExitError
			switch {
			case tc.want == 0 && !errors.Is(err, errExec):
				t.Errorf("the service did not run: %v", err)
			case tc.want != 0 && (!errors.As(err, &ee) || ee.Code != tc.want):
				t.Errorf("want status %d: %v", tc.want, err)
			}
		})
	}
}

// The pending signals are the ones of this run: caught forgets what it
// reported, and a buffer that overflows drops signals without ever blocking the
// runtime that delivers them.
func TestHoldSignalsCaughtForgets(t *testing.T) {
	r := newRig(t)
	deliver := signalRig(t, r)
	release, caught, _ := holdSignals()
	if caught() != 0 {
		t.Error("a signal out of nothing")
	}
	deliver(syscall.SIGHUP)
	if got := caught(); got != int(syscall.SIGHUP) {
		t.Errorf("caught %d", got)
	}
	if got := caught(); got != 0 {
		t.Errorf("the same signal twice: %d", got)
	}
	release()
	if !slices.Equal(r.calls, []string{"release"}) {
		t.Errorf("%v", r.calls)
	}
}

// s6-finish takes away what a run ended while staging left: the staging mount
// of the service (and only of that service), then its directory. Idempotent;
// a mount that is not named sdcreds is refused.
func TestFinishSweepsALeftoverStage(t *testing.T) {
	base := t.TempDir()
	r := newRig(t)
	mine := filepath.Join(base, stagePrefix("web")+"123")
	other := filepath.Join(base, stagePrefix("web2")+"123")
	foreign := filepath.Join(base, ".stage-9999")
	for _, d := range []string{mine, other, foreign} {
		if err := os.MkdirAll(filepath.Join(d, "mnt"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r.layers[filepath.Join(mine, "mnt")] = 2 // a stack
	r.layers[filepath.Join(other, "mnt")] = 1
	ops := r.ops()
	ops.MountSource = func(dir string) (string, bool, error) { return MountTag, r.layers[dir] > 0, nil }
	if err := Finish("web", base, ops); err != nil {
		t.Fatal(err)
	}
	if r.layers[filepath.Join(mine, "mnt")] != 0 {
		t.Error("the stage is still mounted")
	}
	if _, err := os.Lstat(mine); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the stage directory is left: %v", err)
	}
	if r.layers[filepath.Join(other, "mnt")] != 1 {
		t.Error("the stage of another service was unmounted")
	}
	for _, d := range []string{other, foreign} {
		if _, err := os.Lstat(d); err != nil {
			t.Errorf("%s was removed: %v", d, err)
		}
	}
	// idempotent
	if err := Finish("web", base, ops); err != nil {
		t.Errorf("second finish: %v", err)
	}
}

// A mount in a stage that sdcreds did not make is never detached.
func TestFinishRefusesAForeignMountInAStage(t *testing.T) {
	base := t.TempDir()
	r := newRig(t)
	mnt := filepath.Join(base, stagePrefix("web")+"1", "mnt")
	if err := os.MkdirAll(mnt, 0o700); err != nil {
		t.Fatal(err)
	}
	r.layers[mnt] = 1
	ops := r.ops()
	ops.MountSource = func(string) (string, bool, error) { return "tmpfs", true, nil }
	err := Finish("web", base, ops)
	if !errors.Is(err, ErrForeignMount) || slices.Contains(r.calls, "unmount") || r.layers[mnt] != 1 {
		t.Errorf("%v %v", err, r.calls)
	}
}

// A stage that is a symbolic link is not followed.
func TestFinishDoesNotFollowAStageLink(t *testing.T) {
	base, victim := t.TempDir(), t.TempDir()
	os.WriteFile(filepath.Join(victim, "keep"), []byte("x"), 0o600)
	link := filepath.Join(base, stagePrefix("web")+"1")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	r := newRig(t)
	if err := Finish("web", base, r.ops()); err == nil || slices.Contains(r.calls, "unmount") {
		t.Errorf("%v %v", err, r.calls)
	}
	if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
		t.Error("the target of the link was touched")
	}
}

// A failure to remove a stage is reported, and an unreadable base too.
func TestFinishReportsWhatItCannotRemove(t *testing.T) {
	base := t.TempDir()
	stage := filepath.Join(base, stagePrefix("web")+"1")
	if err := os.MkdirAll(filepath.Join(stage, "mnt", "left"), 0o700); err != nil {
		t.Fatal(err)
	}
	r := newRig(t)
	if err := Finish("web", base, r.ops()); err == nil {
		t.Error("a stage that holds a file was reported as removed")
	}
	if _, err := os.Stat(filepath.Join(stage, "mnt", "left")); err != nil {
		t.Errorf("a file was deleted: %v", err)
	}
	if err := sweepStages("web", filepath.Join(base, "absent"), r.ops()); err == nil {
		t.Error("an unreadable base was not reported")
	}
}

// The staging directory is named by the service, and what a name could not
// separate (a prefix of another name) is kept apart.
func TestStagePrefixIsPerService(t *testing.T) {
	a, b := stagePrefix("web"), stagePrefix("web2")
	if a == b || strings.HasPrefix(b, a) || strings.HasPrefix(a, b) || !strings.HasPrefix(a, ".stage-") {
		t.Errorf("%q %q", a, b)
	}
	if long := stagePrefix(strings.Repeat("x", 255)); len(long)+10 > 255 {
		t.Errorf("a service of NameMax bytes cannot be staged: %d", len(long))
	}
}

// The held signals are handed to the starter, the only reader of them from
// then on: a signal that came in the gap before the service was forked is
// delivered once, one that comes after the forwarding began is delivered once,
// and none is delivered twice (HUP and USR1 mean "reload" to a service).
func TestEverySignalIsDeliveredToTheServiceOnce(t *testing.T) {
	r, c := newRig(t), config(t)
	deliver := signalRig(t, r)
	o := r.ops()
	var got []syscall.Signal
	o.StartSignals = func(held <-chan os.Signal, _ User, _, _ []string) (func() (int, error), error) {
		deliver(syscall.SIGHUP) // in the gap: after Run's check, before forwarding
		return func() (int, error) {
			// the forwarder: reads the gap signal first, then the next ones
			got = append(got, (<-held).(syscall.Signal))
			deliver(syscall.SIGUSR1) // after the forwarding began
			got = append(got, (<-held).(syscall.Signal))
			select {
			case s := <-held:
				t.Errorf("%v delivered twice", s)
			default:
			}
			return 0, nil
		}, nil
	}
	if err := Run(c, o); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []syscall.Signal{syscall.SIGHUP, syscall.SIGUSR1}) {
		t.Errorf("delivered %v", got)
	}
}

// When Ops has StartSignals, Start is not used, and Run's own reading of the
// held signals stops at the fork: a signal read by Run's check is not forwarded.
func TestSignalReadByTheCheckIsNotForwarded(t *testing.T) {
	r, c := newRig(t), config(t)
	deliver := signalRig(t, r)
	o := r.ops()
	started := false
	o.Start = func(User, []string, []string) (func() (int, error), error) {
		t.Error("Start used though StartSignals is set")
		return nil, errors.New("no")
	}
	o.StartSignals = func(held <-chan os.Signal, _ User, _, _ []string) (func() (int, error), error) {
		started = true
		select {
		case s := <-held:
			t.Errorf("a signal left over: %v", s)
		default:
		}
		return func() (int, error) { return 0, nil }, nil
	}
	mount := o.Move
	o.Move = func(a, b string) error { deliver(syscall.SIGCONT); return mount(a, b) }
	if err := Run(c, o); err != nil || !started {
		t.Errorf("%v started=%v", err, started)
	}
}

// Decrypted is called after the credentials are read, before the first mount,
// and also when decryption fails.
func TestDecryptedIsCalledBeforeAnythingIsMounted(t *testing.T) {
	for _, fail := range []bool{false, true} {
		r, c := newRig(t), config(t)
		var seen []string
		c.Decrypted = func() { seen = append(seen, "decrypted"); r.calls = append(r.calls, "decrypted") }
		if fail {
			c.Decrypt = func(string, []byte) ([]byte, error) { return nil, errors.New("no key") }
		}
		o := r.ops()
		o.Start = func(User, []string, []string) (func() (int, error), error) {
			return func() (int, error) { return 0, nil }, nil
		}
		err := Run(c, o)
		if (err != nil) != fail {
			t.Errorf("fail=%v: %v", fail, err)
		}
		if len(seen) != 1 {
			t.Errorf("fail=%v: called %d times", fail, len(seen))
		}
		if slices.Index(r.calls, "mount") >= 0 && slices.Index(r.calls, "decrypted") > slices.Index(r.calls, "mount") {
			t.Errorf("fail=%v: after the mount: %v", fail, r.calls)
		}
	}
}

// A sweep that fails still leaves the live credential mount taken away, and
// the error is reported.
func TestFinishTakesTheLiveMountAwayWhenTheSweepFails(t *testing.T) {
	base := t.TempDir()
	r := newRig(t)
	stage := filepath.Join(base, stagePrefix("web")+"1")
	if err := os.MkdirAll(filepath.Join(stage, "mnt", "left"), 0o700); err != nil {
		t.Fatal(err)
	}
	live := Dir(base, "web")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	r.layers[live] = 1
	ops := r.ops()
	ops.MountSource = func(dir string) (string, bool, error) { return MountTag, r.layers[dir] > 0, nil }
	if err := Finish("web", base, ops); err == nil {
		t.Error("the failed sweep was not reported")
	}
	if r.layers[live] != 0 {
		t.Error("the live credential mount was left")
	}
	if _, err := os.Lstat(live); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the credential directory is left: %v", err)
	}
}
