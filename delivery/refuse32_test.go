//go:build unix && !openbsd

package delivery

import (
	"os/exec"
	"strings"
	"testing"
)

// 32-bit OpenBSD is refused: the build must fail, and its message must name the
// reason (delivery/refuse_openbsd_32bit.go). A build that succeeds is the defect.
func TestOpenBSD32bitIsRefused(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain on this host")
	}
	for _, arch := range []string{"386", "arm"} {
		t.Run(arch, func(t *testing.T) {
			cmd := exec.Command(goBin, "build", "-o", "/dev/null", "./delivery/")
			cmd.Dir = ".."
			cmd.Env = append(cmd.Environ(), "GOOS=openbsd", "GOARCH="+arch, "CGO_ENABLED=0")
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("openbsd/%s built: it must be refused", arch)
			}
			if !strings.Contains(string(out), "mfsArgsSize_144_and_the_mount_layout_are_LP64_only") {
				t.Fatalf("openbsd/%s failed, but not with the reason:\n%s", arch, out)
			}
		})
	}
}
