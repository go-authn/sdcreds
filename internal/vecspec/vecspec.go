// Package vecspec describes the interop vectors: the matrix the generator
// (internal/genvectors) runs the real systemd-creds over, the manifest it
// writes, and the deterministic payloads. The tests read the same manifest.
package vecspec

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
)

// Fixtures. The machine id and the host secret are test data and protect nothing.
const (
	Dir       = "testdata/systemd-v262.2"
	MachineID = "0123456789abcdef0123456789abcdef"
	User      = "sdcreds-test"
	UID       = 1000

	// Timestamp is the creation time embedded in every vector (seconds).
	Timestamp = 1700000000
	// NotAfterPast and NotAfterFuture are the two not-after fixtures (seconds).
	NotAfterPast   = 1700000100
	NotAfterFuture = 4102444800
	// NowEarly lies between Timestamp and NotAfterPast; NowLate after it.
	NowEarly = 1700000050
	NowLate  = 1800000000
)

// Class is the outcome of a decryption, as classified from systemd's stderr.
type Class string

// The outcomes the vectors distinguish.
const (
	OK           Class = "ok"
	NameMismatch Class = "name-mismatch"
	Expired      Class = "expired"
	Scope        Class = "scope"
	Auth         Class = "auth"
	Format       Class = "format"
)

// Decrypt is one decryption attempt of a vector and what systemd-creds did.
type Decrypt struct {
	// Name is the expected name; nil means --name= (no validation).
	Name *string `json:"name"`
	// Now is the --timestamp= used for the not-after check, in seconds.
	Now int64 `json:"now"`
	// Scoped says whether --uid= was passed.
	Scoped bool  `json:"scoped"`
	Expect Class `json:"expect"`
}

// Vector is one credential file made by systemd-creds encrypt.
type Vector struct {
	File     string    `json:"file"`
	Mode     string    `json:"mode"` // null, host, host-scoped
	Name     string    `json:"name"` // embedded name, "" for none
	NotAfter int64     `json:"not_after"`
	Payload  string    `json:"payload"` // empty, one, k64
	Tamper   string    `json:"tamper,omitempty"`
	Decrypt  []Decrypt `json:"decrypt"`
}

// Manifest is testdata/systemd-v262.2/manifest.json.
type Manifest struct {
	Systemd   string   `json:"systemd"`
	MachineID string   `json:"machine_id"`
	User      string   `json:"user"`
	UID       uint32   `json:"uid"`
	Timestamp int64    `json:"timestamp"`
	Vectors   []Vector `json:"vectors"`
}

// Payload returns the deterministic plaintext of a payload kind.
func Payload(kind string) []byte {
	switch kind {
	case "empty":
		return []byte{}
	case "one":
		return []byte{0x2a}
	case "k64":
		r := rand.New(rand.NewPCG(1, 262))
		b := make([]byte, 64<<10)
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return b
	}
	panic("vecspec: unknown payload " + kind)
}

// Matrix lists the vectors to generate. A 64 KiB payload is kept to a few
// combinations to bound the size of the repository.
func Matrix() []Vector {
	var vs []Vector
	notAfters := map[string]int64{"inf": 0, "past": NotAfterPast, "future": NotAfterFuture}
	for _, mode := range []string{"null", "host", "host-scoped"} {
		for _, name := range []string{"", "foo"} {
			for _, na := range []string{"inf", "past", "future"} {
				for _, pl := range []string{"empty", "one", "k64"} {
					if pl == "k64" && (name == "" || na != "inf") {
						continue
					}
					vs = append(vs, Vector{
						File:     fmt.Sprintf("%s.name-%s.na-%s.%s.cred", mode, nameTag(name), na, pl),
						Mode:     mode,
						Name:     name,
						NotAfter: notAfters[na],
						Payload:  pl,
					})
				}
			}
		}
	}
	return vs
}

func nameTag(n string) string {
	if n == "" {
		return "none"
	}
	return n
}

// Load reads the manifest in dir.
func Load(dir string) (*Manifest, error) {
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
