//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decrypt writes the plaintext through a fresh private file: a file or a
// symlink already at the destination is replaced, never written through, and
// a wider mode on it is not inherited.
func TestOutputIsWrittenThroughAFreshFile(t *testing.T) {
	dir := env(t)
	enc := mustRun(t, "hunter2", "encrypt", "--with-key=null", "--name=")

	victim := filepath.Join(dir, "victim")
	os.WriteFile(victim, []byte("precious"), 0o644)
	link := filepath.Join(dir, "out-link")
	os.Symlink(victim, link)
	if _, _, err := run(t, enc, "decrypt", "--allow-null", "--name=", "-", link); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "precious" {
		t.Errorf("the symlink target was written through: %q", b)
	}
	st, err := os.Lstat(link)
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Errorf("destination: %v %v", st, err)
	}
	if b, _ := os.ReadFile(link); string(b) != "hunter2" {
		t.Errorf("content %q", b)
	}

	wide := filepath.Join(dir, "wide")
	os.WriteFile(wide, []byte("old"), 0o666)
	os.Chmod(wide, 0o666)
	if _, _, err := run(t, enc, "decrypt", "--allow-null", "--name=", "-", wide); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(wide); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v inherited from the old file", st.Mode().Perm())
	}
	// No temporary file is left, and a failure leaves none either.
	left, _ := filepath.Glob(filepath.Join(dir, ".sdcreds-*"))
	if len(left) != 0 {
		t.Errorf("left over: %v", left)
	}
	err = writeFileAtomic(filepath.Join(dir, "no-such-dir", "x"), []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "no-such-dir") {
		t.Errorf("%v", err)
	}
}
