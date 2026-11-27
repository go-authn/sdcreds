//go:build !openbsd

package exitguard

import "errors"

// WatchExit exists on OpenBSD only, the platform whose standard library cannot
// order a reap before its own bookkeeping.
func WatchExit(int) (<-chan struct{}, error) {
	return nil, errors.New("exitguard: WatchExit is OpenBSD only")
}
