//go:build !unix

package s6

// raise has no signal to send where nothing is held.
var raise = func(int) error { return nil }

// holdSignals has nothing to hold where there is no s6 to signal.
func holdSignals() (release func(), caught func() int) {
	return func() {}, func() int { return 0 }
}
