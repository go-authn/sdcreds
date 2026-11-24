//go:build unix

package s6

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

// helperDeadline bounds a child of the test binary that exercises start or Run:
// one that never returns fails the test that launched it, by name, and is
// killed, instead of holding the package until the 10-minute limit of go test.
const helperDeadline = 60 * time.Second

// helperOutput runs the test binary with args and returns its combined output;
// the child is killed and the test failed if it outlives helperDeadline.
func helperOutput(t *testing.T, env []string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), helperDeadline)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	cmd.Env = env
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("the helper %v did not return within %v: %s", args, helperDeadline, out)
	}
	return out, err
}
