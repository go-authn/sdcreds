package sdcreds_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every action of the CI is pinned to a commit, and the systemd source of the
// interop image is checked against a commit.
func TestCIIsPinnedToCommits(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(".github", "workflows", "*.yml"))
	if len(files) == 0 {
		t.Fatal("no workflow found")
	}
	pinned := regexp.MustCompile(`^\s*-?\s*uses:\s+[\w./-]+@[0-9a-f]{40}(\s|$)`)
	uses := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "uses:") {
				continue
			}
			uses++
			if !pinned.MatchString(line) {
				t.Errorf("%s:%d is not pinned to a commit: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
	if uses == 0 {
		t.Error("no action found")
	}
	d, err := os.ReadFile(filepath.Join("docker", "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^ARG SYSTEMD_COMMIT=[0-9a-f]{40}$`).Match(d) || !strings.Contains(string(d), `rev-parse HEAD)" = "${SYSTEMD_COMMIT}"`) {
		t.Error("the systemd commit is not pinned and checked in docker/Dockerfile")
	}
}
