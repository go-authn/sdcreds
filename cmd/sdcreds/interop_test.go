package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The command line against the real systemd-creds, in both directions, in the
// three modes. SDCREDS_REQUIRE_SYSTEMD=1 (set by CI) makes its absence fatal.
func TestCLIAgainstSystemdCreds(t *testing.T) {
	needHostFiles(t)
	sd, err := exec.LookPath("systemd-creds")
	if err != nil {
		if os.Getenv("SDCREDS_REQUIRE_SYSTEMD") == "1" {
			t.Fatal("systemd-creds is required: ", err)
		}
		t.Skip("systemd-creds is not installed")
	}
	dir := t.TempDir()
	mid := filepath.Join(dir, "machine-id")
	if err := os.WriteFile(mid, []byte(midText), 0o444); err != nil {
		t.Fatal(err)
	}
	// systemd-creds reads /etc/machine-id itself: the container has it set to
	// the same value, else the host mode is skipped.
	if b, _ := os.ReadFile("/etc/machine-id"); string(b) != midText {
		t.Skip("/etc/machine-id is not the test machine id")
	}
	t.Setenv(MachineIDEnv, mid)
	secret := filepath.Join(dir, "credential.secret")
	t.Setenv("SYSTEMD_CREDENTIAL_SECRET", secret)
	if out, err := exec.Command(sd, "setup").CombinedOutput(); err != nil {
		t.Fatalf("setup: %v: %s", err, out)
	}
	plain := filepath.Join(dir, "plain")
	os.WriteFile(plain, []byte("hunter2\n"), 0o600)

	for _, mode := range []string{"null", "host"} {
		// ours -> systemd
		ours := filepath.Join(dir, "ours-"+mode)
		mustRun(t, "", "encrypt", "--with-key="+mode, plain, ours)
		out, err := exec.Command(sd, "decrypt", "--allow-null", ours, "-").Output()
		if err != nil || string(out) != "hunter2\n" {
			t.Errorf("%s: systemd decrypts ours: %q %v", mode, out, err)
		}
		// systemd -> ours
		theirs := filepath.Join(dir, "theirs-"+mode)
		if o, err := exec.Command(sd, "encrypt", "--with-key="+mode, plain, theirs).CombinedOutput(); err != nil {
			t.Fatalf("%s: encrypt: %v: %s", mode, err, o)
		}
		if got := mustRun(t, "", "decrypt", "--allow-null", theirs); got != "hunter2\n" {
			t.Errorf("%s: we decrypt theirs: %q", mode, got)
		}
	}
}
