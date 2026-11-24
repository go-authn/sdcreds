//go:build unix

package s6

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The plaintext does not stay in memory while the service runs: it is wiped
// once it is in the file system, before Start and before wait.
func TestPlaintextIsWipedBeforeTheServiceRuns(t *testing.T) {
	var kept [][]byte
	r, c := newRig(t), config(t)
	c.Decrypt = func(name string, enc []byte) ([]byte, error) {
		pt, err := nullDecrypt(name, enc)
		kept = append(kept, pt)
		return pt, err
	}
	zero := func(when string) {
		if len(kept) != 2 {
			t.Fatalf("%d decryptions", len(kept))
		}
		for _, b := range kept {
			if !bytes.Equal(b, make([]byte, len(b))) {
				t.Errorf("%s: plaintext still in memory: %q", when, b)
			}
		}
	}
	o := r.ops()
	o.Start = func(User, []string, []string) (func() (int, error), error) {
		zero("at Start")
		return func() (int, error) { zero("at wait"); return 0, nil }, nil
	}
	if err := Run(c, o); err != nil {
		t.Fatal(err)
	}
}

const holdHelperEnv = "SDCREDS_S6_HOLD_HELPER"

// TestHoldHelper is the child of TestASecondSignalDuringCleanUpDoesNotEndTheRun:
// it sends itself TERM from inside the clean-up, after the service ended.
func TestHoldHelper(t *testing.T) {
	mode := os.Getenv(holdHelperEnv)
	if mode == "" {
		t.Skip("child of TestASecondSignalDuringCleanUpDoesNotEndTheRun")
	}
	r, c := newRig(t), config(t)
	o := r.ops()
	waited := false
	o.Start = func(User, []string, []string) (func() (int, error), error) {
		return func() (int, error) { waited = true; return 0, nil }, nil
	}
	unmount := o.Unmount
	o.Unmount = func(dir string) error {
		if waited {
			syscall.Kill(os.Getpid(), syscall.SIGTERM)
			time.Sleep(200 * time.Millisecond) // the signal is delivered, or this process is gone
		}
		return unmount(dir)
	}
	if mode == "start-error" {
		o.Start = func(User, []string, []string) (func() (int, error), error) {
			waited = true
			return nil, errors.New("no exec")
		}
	}
	err := Run(c, o)
	fmt.Println("survived", err)
	if r.layers[Dir(c.BaseDir, "web")] != 0 {
		fmt.Println("mount left")
	}
}

func TestASecondSignalDuringCleanUpDoesNotEndTheRun(t *testing.T) {
	for _, mode := range []string{"after-wait", "start-error"} {
		out, err := helperOutput(t, append(os.Environ(), holdHelperEnv+"="+mode), "-test.run=^TestHoldHelper$", "-test.v")
		if err != nil || !strings.Contains(string(out), "survived") || strings.Contains(string(out), "mount left") {
			t.Errorf("%s: the run was ended by the signal: %v\n%s", mode, err, out)
		}
	}
}
