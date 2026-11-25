package delivery

import (
	"fmt"
	"path/filepath"
	"regexp"
)

var serviceRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidService reports whether s is a service name of `sdcreds run`: a lower
// case letter or digit, then up to 63 of letters, digits, '_' and '-'. It cannot
// start with '.', so the lock file of a service never collides with the
// directory of another.
func ValidService(s string) bool { return serviceRE.MatchString(s) }

// LockPath is the lock file of a service: Base/.SERVICE.lock.
func LockPath(base, service string) (string, error) {
	if !ValidService(service) {
		return "", fmt.Errorf("%w: %q", ErrBadService, service)
	}
	return filepath.Join(base, "."+service+".lock"), nil
}
