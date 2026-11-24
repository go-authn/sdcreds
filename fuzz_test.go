package sdcreds_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/internal/vecspec"
)

// seeds feeds the fuzzers with the credentials systemd-creds wrote: the real
// formats are the corpus, plus the entries committed in testdata/fuzz.
func seeds(f *testing.F, armored bool) {
	files, _ := filepath.Glob(filepath.Join(vecspec.Dir, "*.cred"))
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		if info, _ := os.Stat(p); info.Size() > 8192 {
			continue // keep the corpus small; the 64 KiB vectors only bloat it
		}
		if !armored {
			if b, err = sdcreds.Unarmor(b); err != nil {
				f.Fatal(err)
			}
		}
		f.Add(b)
	}
}

func FuzzParse(f *testing.F) {
	seeds(f, false)
	f.Fuzz(func(t *testing.T, blob []byte) {
		h, err := sdcreds.Parse(blob)
		if err != nil {
			if h != nil {
				t.Fatal("header returned with an error")
			}
			return
		}
		// Invariants of an accepted header: the AAD lies inside the blob, and the
		// IV has the size the header declares (systemd sets the AEAD IV length
		// from the header, so it need not be 12).
		if h.AADLen() <= 0 || h.AADLen() > len(blob) || h.AADLen()%8 != 0 || len(h.IV) == 0 || uint32(len(h.IV)) != h.IVSize || h.KeySize != 32 || h.TagSize != 16 {
			t.Fatalf("bad header %+v for %d bytes", h, len(blob))
		}
	})
}

func FuzzDecrypt(f *testing.F) {
	seeds(f, false)
	key := sdcreds.StaticHostKey(secret4k)
	f.Fuzz(func(t *testing.T, blob []byte) {
		o := sdcreds.DecryptOptions{HostKey: key, AllowNull: true, Timestamp: 1, Scope: scoped(1000, "u", fixedMID)}
		pt, md, err := sdcreds.Decrypt(blob, o)
		if err != nil {
			if pt != nil || md != (sdcreds.Metadata{}) {
				t.Fatal("data returned with an error")
			}
			return
		}
		// Anything that authenticates under a key the fuzzer cannot know is a
		// credential we made: re-encrypting its payload must work.
		if _, err := sdcreds.Encrypt(pt, sdcreds.EncryptOptions{Key: sdcreds.IDNull, Timestamp: 1}); err != nil && !errors.Is(err, sdcreds.ErrTooLarge) {
			t.Fatal(err)
		}
	})
}

// FuzzRoundTrip: whatever Encrypt writes, Decrypt reads back unchanged.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("hello"), "name", uint64(5), uint64(0))
	f.Add([]byte{}, "", uint64(0), uint64(9))
	key := sdcreds.StaticHostKey(secret4k)
	f.Fuzz(func(t *testing.T, payload []byte, name string, ts, na uint64) {
		for _, id := range []sdcreds.KeyID{sdcreds.IDNull, sdcreds.IDHost, sdcreds.IDHostScoped} {
			o := sdcreds.EncryptOptions{Key: id, HostKey: key, Name: name, Timestamp: ts, NotAfter: na, Scope: scoped(7, "u", fixedMID)}
			blob, err := sdcreds.Encrypt(payload, o)
			if err != nil {
				if !errors.Is(err, sdcreds.ErrInvalid) && !errors.Is(err, sdcreds.ErrTooLarge) {
					t.Fatalf("unexpected error class: %v", err)
				}
				continue
			}
			d := sdcreds.DecryptOptions{HostKey: key, AllowNull: true, Timestamp: sdcreds.Infinity, Scope: o.Scope}
			if id != sdcreds.IDHostScoped {
				d.Scope = nil
			}
			got, md, err := sdcreds.Decrypt(blob, d)
			if err != nil || !bytes.Equal(got, payload) || md.Name != name {
				t.Fatalf("round trip: %v", err)
			}
		}
	})
}

func FuzzUnarmor(f *testing.F) {
	seeds(f, true)
	f.Add([]byte("YQ=="))
	f.Fuzz(func(t *testing.T, text []byte) {
		blob, err := sdcreds.Unarmor(text)
		if err != nil {
			return
		}
		// What decodes must re-encode to something that decodes to the same bytes.
		again, err := sdcreds.Unarmor([]byte(sdcreds.Armor(blob, sdcreds.ArmorWidth)))
		if err != nil || !bytes.Equal(again, blob) {
			t.Fatalf("armor round trip: %v", err)
		}
	})
}
