//go:build !unix

package s6

import (
	"fmt"
	"os"
)

// fchmodDir sets the mode of a directory (off unix there is no umask to defeat).
var fchmodDir = func(path string, mode os.FileMode) error { return os.Chmod(path, mode) }

// openSource opens a credential file for reading; replaced by the tests. Off
// unix there is no O_NOFOLLOW, so a link is refused by a check first.
var openSource = func(path string) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("a symbolic link is not followed")
	}
	return os.Open(path)
}
