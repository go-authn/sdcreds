package sdcreds_test

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/internal/vecspec"
)

const micro = 1_000_000

func loadVectors(t *testing.T) *vecspec.Manifest {
	t.Helper()
	m, err := vecspec.Load(vecspec.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Vectors) < 40 {
		t.Fatalf("only %d vectors in the manifest", len(m.Vectors))
	}
	return m
}

func machineID(t *testing.T, m *vecspec.Manifest) [16]byte {
	t.Helper()
	id, err := sdcreds.ParseMachineID([]byte(m.MachineID))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// hostKey copies the vector host secret under mode 0400, as the checkout
// does not preserve it, and returns a source bound to the vector machine id.
func hostKey(t *testing.T, m *vecspec.Manifest) sdcreds.HostKeySource {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vecspec.Dir, "host.secret"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "host.secret")
	if err := os.WriteFile(p, b, 0o400); err != nil {
		t.Fatal(err)
	}
	return sdcreds.HostKeyFile{Path: p, MachineID: machineID(t, m)}
}

func scopeOf(t *testing.T, m *vecspec.Manifest) *sdcreds.Scope {
	return &sdcreds.Scope{UID: m.UID, Username: m.User, MachineID: machineID(t, m)}
}

func readBlob(t *testing.T, f string) (text, blob []byte) {
	t.Helper()
	text, err := os.ReadFile(filepath.Join(vecspec.Dir, f))
	if err != nil {
		t.Fatal(err)
	}
	blob, err = sdcreds.Unarmor(text)
	if err != nil {
		t.Fatal(err)
	}
	return text, blob
}

func wantErr(c vecspec.Class) error {
	switch c {
	case vecspec.NameMismatch:
		return sdcreds.ErrNameMismatch
	case vecspec.Expired:
		return sdcreds.ErrExpired
	case vecspec.Scope:
		return sdcreds.ErrScope
	case vecspec.Auth:
		return sdcreds.ErrAuth
	case vecspec.Format:
		return sdcreds.ErrFormat
	}
	return nil
}

// TestSystemdVectorsDecrypt opens every credential written by the real
// systemd-creds 262.2 and requires the same outcome as systemd, case by case.
func TestSystemdVectorsDecrypt(t *testing.T) {
	m := loadVectors(t)
	hk := hostKey(t, m)
	cases := 0
	for _, v := range m.Vectors {
		_, blob := readBlob(t, v.File)
		for _, d := range v.Decrypt {
			cases++
			o := sdcreds.DecryptOptions{HostKey: hk, Name: d.Name, Timestamp: uint64(d.Now) * micro, AllowNull: true}
			if d.Scoped {
				o.Scope = scopeOf(t, m)
			}
			got, md, err := sdcreds.Decrypt(blob, o)
			label := v.File
			if d.Name != nil {
				label += " name=" + *d.Name
			}
			if d.Expect == vecspec.OK {
				if err != nil {
					t.Errorf("%s now=%d scoped=%v: %v", label, d.Now, d.Scoped, err)
					continue
				}
				if !bytes.Equal(got, vecspec.Payload(v.Payload)) {
					t.Errorf("%s: payload differs", label)
				}
				if md.Name != v.Name || md.Timestamp != uint64(m.Timestamp)*micro {
					t.Errorf("%s: metadata %+v", label, md)
				}
				continue
			}
			if !errors.Is(err, wantErr(d.Expect)) {
				t.Errorf("%s now=%d scoped=%v: want %s, got %v", label, d.Now, d.Scoped, d.Expect, err)
			}
			if d.Expect == vecspec.Format && errors.Is(err, sdcreds.ErrAuth) {
				t.Errorf("%s: format error reported as authentication failure", label)
			}
		}
	}
	if cases < 200 {
		t.Fatalf("only %d cases ran", cases)
	}
}

func encOptions(t *testing.T, m *vecspec.Manifest, v vecspec.Vector, iv []byte) sdcreds.EncryptOptions {
	o := sdcreds.EncryptOptions{
		Name:      v.Name,
		Timestamp: uint64(m.Timestamp) * micro,
		NotAfter:  uint64(v.NotAfter) * micro,
	}
	if iv != nil {
		o.Rand = bytes.NewReader(iv)
	}
	switch v.Mode {
	case "null":
		o.Key = sdcreds.IDNull
	case "host":
		o.Key, o.HostKey = sdcreds.IDHost, hostKey(t, m)
	case "host-scoped":
		o.Key, o.HostKey, o.Scope = sdcreds.IDHostScoped, hostKey(t, m), scopeOf(t, m)
	}
	return o
}

// TestEncryptReproducesSystemd gives Encrypt the IV systemd drew and requires
// the very same bytes, and the same armoured text, as the real binary wrote.
func TestEncryptReproducesSystemd(t *testing.T) {
	m := loadVectors(t)
	n := 0
	for _, v := range m.Vectors {
		if v.Tamper != "" {
			continue
		}
		text, blob := readBlob(t, v.File)
		h, err := sdcreds.Parse(blob)
		if err != nil {
			t.Fatalf("%s: %v", v.File, err)
		}
		got, err := sdcreds.Encrypt(vecspec.Payload(v.Payload), encOptions(t, m, v, h.IV))
		if err != nil {
			t.Fatalf("%s: %v", v.File, err)
		}
		if !bytes.Equal(got, blob) {
			t.Errorf("%s: Encrypt differs from systemd-creds", v.File)
		}
		if a := sdcreds.Armor(blob, sdcreds.ArmorWidth); a != string(text) {
			t.Errorf("%s: Armor differs from the file systemd wrote", v.File)
		}
		n++
	}
	if n < 39 {
		t.Fatalf("only %d vectors reproduced", n)
	}
}

// TestHeaderOfVectors checks the header fields confirmed against systemd.
func TestHeaderOfVectors(t *testing.T) {
	m := loadVectors(t)
	for _, v := range m.Vectors {
		if v.Tamper != "" {
			continue
		}
		_, blob := readBlob(t, v.File)
		h, err := sdcreds.Parse(blob)
		if err != nil {
			t.Fatalf("%s: %v", v.File, err)
		}
		want := map[string]sdcreds.KeyID{"null": sdcreds.IDNull, "host": sdcreds.IDHost, "host-scoped": sdcreds.IDHostScoped}[v.Mode]
		if h.ID != want || h.KeySize != 32 || h.BlockSize != 1 || h.IVSize != 12 || h.TagSize != 16 || len(h.IV) != 12 {
			t.Errorf("%s: header %+v", v.File, h)
		}
		if h.ID.Scoped() != (v.Mode == "host-scoped") || h.ID.UsesHostKey() != (v.Mode != "null") {
			t.Errorf("%s: id predicates", v.File)
		}
		if h.AADLen()%8 != 0 || h.AADLen() >= len(blob) {
			t.Errorf("%s: AAD length %d of %d", v.File, h.AADLen(), len(blob))
		}
	}
}

func systemdCreds(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("systemd-creds")
	if err != nil {
		if os.Getenv("SDCREDS_REQUIRE_SYSTEMD") == "1" {
			t.Fatal("SDCREDS_REQUIRE_SYSTEMD=1 but systemd-creds is not in PATH")
		}
		t.Skip("systemd-creds not in PATH (the interop image provides it)")
	}
	return p
}

// TestSystemdDecryptsOurs makes the real systemd-creds open what Encrypt
// wrote, for every mode, the other direction of the interop check.
func TestSystemdDecryptsOurs(t *testing.T) {
	bin := systemdCreds(t)
	m := loadVectors(t)
	secret, err := filepath.Abs(filepath.Join(vecspec.Dir, "host.secret"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	n := 0
	for _, v := range m.Vectors {
		if v.Tamper != "" || v.NotAfter == vecspec.NotAfterPast || v.Payload == "k64" {
			continue
		}
		blob, err := sdcreds.Encrypt(vecspec.Payload(v.Payload), encOptions(t, m, v, nil))
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(dir, v.File)
		if err := os.WriteFile(f, []byte(sdcreds.Armor(blob, sdcreds.ArmorWidth)), 0o600); err != nil {
			t.Fatal(err)
		}
		args := []string{"decrypt", "--allow-null", "--name=" + v.Name}
		if v.Mode == "host-scoped" {
			args = append(args, "--uid=1000")
		}
		cmd := exec.Command(bin, append(args, f, "-")...)
		cmd.Env = append(os.Environ(), "SYSTEMD_CREDENTIAL_SECRET="+secret)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			t.Errorf("%s: systemd-creds: %v: %s", v.File, err, errb.String())
			continue
		}
		if !bytes.Equal(out.Bytes(), vecspec.Payload(v.Payload)) {
			t.Errorf("%s: systemd decrypted a different payload", v.File)
		}
		n++
	}
	if n < 20 {
		t.Fatalf("only %d credentials checked", n)
	}
}
