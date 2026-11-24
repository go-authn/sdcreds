//go:build !unix

package s6

import "os"

// holdSignals has nothing to hold where there is no s6 to signal.
func holdSignals() (release func(), caught func() int, held <-chan os.Signal) {
	return func() {}, func() int { return 0 }, nil
}
