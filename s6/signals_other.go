//go:build !unix

package s6

// holdSignals has nothing to hold where there is no s6 to signal.
func holdSignals() (release func(), caught func() int) {
	return func() {}, func() int { return 0 }
}
