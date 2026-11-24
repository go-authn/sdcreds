package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// openTemp creates the temporary file; a variable so a test can make the write
// fail.
var openTemp = openExclusive

// writeFileAtomic puts data at path with mode 0600 through a fresh file that is
// created exclusively (never through an existing file or symlink) in the same
// directory, synced, and renamed into place. A pre-existing file or symlink at
// path is replaced, not written through, and keeps no wider mode.
func writeFileAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	var tmp *os.File
	var name string
	for range 8 {
		var r [8]byte
		rand.Read(r[:]) // never fails since Go 1.24
		name = filepath.Join(dir, ".sdcreds-"+hex.EncodeToString(r[:])+".tmp")
		tmp, err = openTemp(name)
		if !errors.Is(err, os.ErrExist) {
			break
		}
	}
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.Remove(name)
		}
	}()
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return err
	}
	return os.Rename(name, path)
}
