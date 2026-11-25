package delivery

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// U8: the table pins exactly the files that are committed, byte for byte, and
// one file per size class.
func TestImageManifestMatchesTheFiles(t *testing.T) {
	files, err := filepath.Glob("images/ffs-*MiB.gz")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		got = append(got, filepath.Base(f))
	}
	var want []string
	for mib := range imageSHA256 {
		want = append(want, fmt.Sprintf("ffs-%dMiB.gz", mib))
	}
	sort.Strings(got)
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("images on disk %v, pinned %v", got, want)
	}
	for mib, pin := range imageSHA256 {
		b, err := os.ReadFile(fmt.Sprintf("images/ffs-%dMiB.gz", mib))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if h := hex.EncodeToString(sum[:]); h != pin {
			t.Errorf("%d MiB: the file is %s, the manifest says %s", mib, h, pin)
		}
		if err := verifyImage(mib, b); err != nil {
			t.Errorf("%d MiB: %v", mib, err)
		}
		if len(b) > maxImageGz {
			t.Errorf("%d MiB: %d bytes, above the %d read bound", mib, len(b), maxImageGz)
		}
	}
}

// Every size class a helper can be asked for has an image pinned.
func TestEveryClassHasAPinnedImage(t *testing.T) {
	for _, c := range classes {
		if _, ok := imageSHA256[c.MiB]; !ok {
			t.Errorf("class %d MiB has no pinned image", c.MiB)
		}
	}
	if len(classes) != len(imageSHA256) {
		t.Errorf("%d classes, %d pinned images", len(classes), len(imageSHA256))
	}
}

func TestVerifyImageRefusesAChangedImage(t *testing.T) {
	b, err := os.ReadFile("images/ffs-1MiB.gz")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyImage(1, b); err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), b...)
	changed[len(changed)/2] ^= 1
	if err := verifyImage(1, changed); !errors.Is(err, ErrImageDigest) {
		t.Fatalf("a flipped bit: %v", err)
	}
	if err := verifyImage(1, append(append([]byte(nil), b...), 0)); !errors.Is(err, ErrImageDigest) {
		t.Fatalf("a trailing byte: %v", err)
	}
	if err := verifyImage(1, nil); !errors.Is(err, ErrImageDigest) {
		t.Fatalf("empty: %v", err)
	}
	if err := verifyImage(3, b); !errors.Is(err, ErrImageDigest) {
		t.Fatalf("a size with no pin: %v", err)
	}
	// An image checked against the pin of another size.
	if err := verifyImage(2, b); !errors.Is(err, ErrImageDigest) {
		t.Fatalf("1 MiB image under the 2 MiB pin: %v", err)
	}
}
