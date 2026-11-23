// Command genvectors regenerates testdata/systemd-v262.2 with the REAL
// systemd-creds. Run it inside the interop image (docker/Dockerfile) from the
// repository root:
//
//	docker run --rm -v "$PWD":/src/sdcreds sdcreds-interop go run ./internal/genvectors
//
// It needs root (it writes /etc/machine-id) and the user in vecspec.User.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/internal/vecspec"
)

func main() {
	err := run(vecspec.Dir, "/etc/machine-id", func(args ...string) *exec.Cmd {
		return exec.Command("systemd-creds", args...)
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "genvectors:", err)
		os.Exit(1)
	}
}

// Seams for the tests: neither can fail on a real system.
var (
	absPath   = filepath.Abs
	machineID = vecspec.MachineID
)

type creds struct {
	secret  string
	command func(args ...string) *exec.Cmd
}

func (c creds) cmd(args ...string) *exec.Cmd {
	cmd := c.command(args...)
	cmd.Env = append(os.Environ(), "SYSTEMD_CREDENTIAL_SECRET="+c.secret)
	return cmd
}

// writeSecret writes the private copy of the host secret; a variable for the tests.
var writeSecret = os.WriteFile

// run writes the vectors and the manifest into dir, with the machine id
// written to idPath, using command to start systemd-creds.
func run(dir, idPath string, command func(args ...string) *exec.Cmd) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(idPath, []byte(machineID+"\n"), 0o444); err != nil {
		return err
	}
	abs, err := absPath(dir)
	if err != nil {
		return err
	}
	c := creds{secret: filepath.Join(abs, "host.secret"), command: command}
	if _, err := os.Stat(c.secret); errors.Is(err, os.ErrNotExist) {
		if out, err := c.cmd("setup").CombinedOutput(); err != nil {
			return fmt.Errorf("setup: %v: %s", err, out)
		}
	}
	// The secret must carry the app-specific machine id prefix: that proves
	// AppSpecificID against the real binary.
	raw, err := os.ReadFile(c.secret)
	if err != nil {
		return err
	}
	mid, err := sdcreds.ParseMachineID([]byte(machineID))
	if err != nil {
		return err
	}
	want := sdcreds.HostSecretMachineID(mid)
	if !bytes.Equal(raw[:16], want[:]) {
		return fmt.Errorf("host secret prefix %x != AppSpecificID %x", raw[:16], want)
	}

	tmp, err := os.MkdirTemp("", "genvectors")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	// systemd-creds refuses a secret it does not own privately (the checkout
	// belongs to another user in a container): use a private copy.
	c.secret = filepath.Join(tmp, "host.secret")
	if err := writeSecret(c.secret, raw, 0o400); err != nil {
		return err
	}

	m := vecspec.Manifest{Systemd: "262.2", MachineID: machineID, User: vecspec.User, UID: vecspec.UID, Timestamp: vecspec.Timestamp}
	vectors := vecspec.Matrix()
	for i := range vectors {
		v := &vectors[i]
		if err := encrypt(c, tmp, dir, v); err != nil {
			return fmt.Errorf("%s: %w", v.File, err)
		}
		v.Decrypt, err = decryptCases(c, dir, v)
		if err != nil {
			return fmt.Errorf("%s: %w", v.File, err)
		}
	}
	m.Vectors = vectors

	// Tampered variants of one host vector, classified by systemd itself.
	base := "host.name-foo.na-inf.one.cred"
	for _, t := range []string{"flip-iv", "flip-ciphertext", "flip-tag", "truncate-tag", "truncate-header"} {
		v := vecspec.Vector{File: strings.TrimSuffix(base, ".cred") + "." + t + ".cred", Mode: "host", Name: "foo", Payload: "one", Tamper: t}
		if err := doTamper(dir, base, &v); err != nil {
			return err
		}
		v.Decrypt, err = decryptCases(c, dir, &v)
		if err != nil {
			return fmt.Errorf("%s: %w", v.File, err)
		}
		m.Vectors = append(m.Vectors, v)
	}

	// Cannot fail: the manifest holds only strings and numbers.
	b, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(filepath.Join(dir, "manifest.json"), append(b, '\n'), 0o644)
}

func withKey(mode string) string {
	if mode == "null" {
		return "null"
	}
	return "host"
}

func encrypt(c creds, tmp, dir string, v *vecspec.Vector) error {
	plain := filepath.Join(tmp, "plain")
	if err := os.WriteFile(plain, vecspec.Payload(v.Payload), 0o600); err != nil {
		return err
	}
	args := []string{"encrypt", "--with-key=" + withKey(v.Mode), fmt.Sprintf("--timestamp=@%d", vecspec.Timestamp), "--name=" + v.Name}
	if v.NotAfter != 0 {
		args = append(args, fmt.Sprintf("--not-after=@%d", v.NotAfter))
	}
	if v.Mode == "host-scoped" {
		args = append(args, fmt.Sprintf("--uid=%d", vecspec.UID))
	}
	args = append(args, plain, filepath.Join(dir, v.File))
	out, err := c.cmd(args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemd-creds %v: %v: %s", args, err, out)
	}
	return nil
}

func ptr(s string) *string { return &s }

// decryptCases runs the real decryption for the cases of one vector.
func decryptCases(c creds, dir string, v *vecspec.Vector) ([]vecspec.Decrypt, error) {
	scoped := v.Mode == "host-scoped"
	var cases []vecspec.Decrypt
	names := []*string{nil}
	if v.Name != "" {
		names = append(names, ptr(v.Name), ptr("bar"))
	} else {
		names = append(names, ptr("bar"))
	}
	for _, name := range names {
		for _, now := range []int64{vecspec.NowEarly, vecspec.NowLate} {
			cases = append(cases, vecspec.Decrypt{Name: name, Now: now, Scoped: scoped})
		}
	}
	// Wrong scope: a scoped credential without --uid, an unscoped one with it.
	cases = append(cases, vecspec.Decrypt{Name: nil, Now: vecspec.NowEarly, Scoped: !scoped})

	for i := range cases {
		d := &cases[i]
		args := []string{"decrypt", "--allow-null", fmt.Sprintf("--timestamp=@%d", d.Now)}
		if d.Name == nil {
			args = append(args, "--name=")
		} else {
			args = append(args, "--name="+*d.Name)
		}
		if d.Scoped {
			args = append(args, fmt.Sprintf("--uid=%d", vecspec.UID))
		}
		args = append(args, filepath.Join(dir, v.File), "-")
		cmd := c.cmd(args...)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		if err == nil {
			if v.Tamper == "" && !bytes.Equal(stdout.Bytes(), vecspec.Payload(v.Payload)) {
				return nil, fmt.Errorf("%v: decrypted payload differs", args)
			}
			d.Expect = vecspec.OK
			continue
		}
		d.Expect = classify(stderr.String())
		if d.Expect == "" {
			return nil, fmt.Errorf("%v: unclassified failure: %s", args, stderr.String())
		}
	}
	return cases, nil
}

// classify maps systemd's stderr to an outcome class (messages of cu.c).
func classify(stderr string) vecspec.Class {
	switch {
	case strings.Contains(stderr, "does not match filename"):
		return vecspec.NameMismatch
	case strings.Contains(stderr, "time passed"):
		return vecspec.Expired
	case strings.Contains(stderr, "scoped to"):
		return vecspec.Scope
	case strings.Contains(stderr, "Decryption failed"):
		return vecspec.Auth
	case strings.Contains(stderr, "too short"), strings.Contains(stderr, "Unexpected"), strings.Contains(stderr, "Failed to read encrypted"):
		return vecspec.Format
	}
	return ""
}

func doTamper(dir, base string, v *vecspec.Vector) error {
	text, err := os.ReadFile(filepath.Join(dir, base))
	if err != nil {
		return err
	}
	blob, err := sdcreds.Unarmor(text)
	if err != nil {
		return err
	}
	switch v.Tamper {
	case "flip-iv":
		blob[32] ^= 1
	case "flip-ciphertext":
		blob[len(blob)-17] ^= 1
	case "flip-tag":
		blob[len(blob)-1] ^= 1
	case "truncate-tag":
		blob = blob[:len(blob)-1]
	case "truncate-header":
		blob = blob[:20]
	}
	return os.WriteFile(filepath.Join(dir, v.File), []byte(sdcreds.Armor(blob, sdcreds.ArmorWidth)), 0o644)
}
