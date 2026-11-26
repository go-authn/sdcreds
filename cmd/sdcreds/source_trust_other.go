//go:build !unix

package main

import (
	"os"
	"path/filepath"

	"github.com/go-authn/sdcreds/s6"
)

// sourceReader reads the directory without judging its path: s6-run is Linux
// only (its real operations report ErrUnsupported here), so this reader serves
// the tests that run the command with scripted operations. There is no trust
// walk off unix.
var sourceReader = readPlainSource

func readPlainSource(dir string) ([]s6.Sealed, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []s6.Sealed
	for _, e := range ents {
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, s6.Sealed{Name: e.Name(), Data: raw})
	}
	return out, nil
}
