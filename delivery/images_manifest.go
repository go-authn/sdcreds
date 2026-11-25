package delivery

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// imageSHA256 pins the embedded FFS images: the sha256 of each committed
// ffs-<N>MiB.gz. The helper writes one of them into the memory file system that
// holds the credentials, as root; a changed image is a changed file system that
// the kernel then mounts. It is checked before a byte is decompressed, and a
// test holds this table to the files. After regenerating the images with
// internal/genimg, the failing test prints the new sums to put here.
var imageSHA256 = map[int]string{
	1:  "388be611c039dbf1017c64508a2ac5a3de21fe2c8f082be5d0c1691029b77b5a",
	2:  "dffe9f7bbc67aea195e0d203437d8f4075babc8a70dfa02e778535c5270d4ebc",
	4:  "8164fa00eb3237f41c2fc185d5cbb7f1a519c7de952ece562814ce5d8b120237",
	8:  "3b10af436999f85d717345df2e2a8dae0f7a813f3f6ad8de7fc8dcba4800da30",
	16: "ace43257afe97240952011ba716e0f419d55ae3a173a29248aea4a97f40b9ab7",
	32: "c1e9be3eb0cc8512708342ce7b75d9ef22eaf0d059202d4c3a92e6725ee2f5ae",
	64: "1a9b82a44a5af92b6f094cc8991380f1759ad7909ed8c9add2cbcc7b44ba7648",
}

// maxImageGz bounds what is read of an embedded image before it is judged.
const maxImageGz = 1 << 20

// ErrImageDigest is an embedded image that is not the one that was pinned.
var ErrImageDigest = fmt.Errorf("delivery: embedded image does not match its pinned sha256")

// verifyImage judges the compressed bytes of the image of mib MiB.
func verifyImage(mib int, gz []byte) error {
	want, ok := imageSHA256[mib]
	if !ok {
		return fmt.Errorf("%w: no digest for %d MiB", ErrImageDigest, mib)
	}
	sum := sha256.Sum256(gz)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(want)) != 1 {
		return fmt.Errorf("%w: %d MiB", ErrImageDigest, mib)
	}
	return nil
}
