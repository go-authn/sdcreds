package vecspec

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestPayload(t *testing.T) {
	if p := Payload("empty"); p == nil || len(p) != 0 {
		t.Errorf("empty: %v", p)
	}
	if !bytes.Equal(Payload("one"), []byte{0x2a}) {
		t.Error("one")
	}
	a, b := Payload("k64"), Payload("k64")
	if len(a) != 64<<10 || !bytes.Equal(a, b) {
		t.Error("k64 must be 64 KiB and deterministic")
	}
	if bytes.Equal(a[:64], make([]byte, 64)) {
		t.Error("k64 payload is all zero")
	}
	defer func() {
		if recover() == nil {
			t.Error("an unknown payload must panic")
		}
	}()
	Payload("nope")
}

func TestMatrix(t *testing.T) {
	vs := Matrix()
	if len(vs) != 39 {
		t.Fatalf("%d vectors", len(vs))
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if seen[v.File] {
			t.Errorf("duplicate %s", v.File)
		}
		seen[v.File] = true
		if v.Payload == "k64" && (v.Name == "" || v.NotAfter != 0) {
			t.Errorf("64 KiB vector %s outside the bounded set", v.File)
		}
	}
	for _, f := range []string{"null.name-none.na-inf.empty.cred", "host.name-foo.na-past.one.cred", "host-scoped.name-foo.na-future.empty.cred", "host.name-foo.na-inf.k64.cred"} {
		if !seen[f] {
			t.Errorf("missing %s", f)
		}
	}
	if !(Timestamp < NowEarly && NowEarly < NotAfterPast && NotAfterPast < NowLate && NowLate < NotAfterFuture) {
		t.Error("fixture times out of order")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); !os.IsNotExist(err) {
		t.Errorf("missing manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("bad JSON accepted")
	}
	good := `{"systemd":"262.2","uid":7,"vectors":[{"file":"a","decrypt":[{"name":null,"now":1,"scoped":true,"expect":"ok"}]}]}`
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	m, err := Load(dir)
	if err != nil || m.UID != 7 || m.Vectors[0].Decrypt[0].Name != nil || !m.Vectors[0].Decrypt[0].Scoped || m.Vectors[0].Decrypt[0].Expect != OK {
		t.Fatalf("%+v %v", m, err)
	}
}
