//go:build unix

package s6

import (
	"fmt"
	"os"
	"syscall"
)

// geteuid is replaced by the tests.
var geteuid = os.Geteuid

// checkBase refuses a base directory that someone other than root (or the user
// running the program) owns, or that group or others can write to: they could
// otherwise redirect where the credentials are mounted and what is unmounted.
func checkBase(base string) error {
	st, err := os.Stat(base)
	if err != nil {
		return err
	}
	return checkBaseInfo(base, st, geteuid())
}

func checkBaseInfo(base string, st os.FileInfo, euid int) error {
	if !st.IsDir() {
		return fmt.Errorf("s6: base directory %s is not a directory", base)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Uid != 0 && int64(sys.Uid) != int64(euid) {
		return fmt.Errorf("s6: base directory %s is owned by uid %d, refusing", base, sys.Uid)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("s6: base directory %s is writable by group or others (%v), refusing", base, st.Mode().Perm())
	}
	return nil
}
