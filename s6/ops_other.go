//go:build !linux

package s6

func unsupported0() error { return ErrUnsupported }

// Real returns Ops that all report ErrUnsupported: the credential directory
// needs Linux mounts.
func Real() Ops {
	return Ops{
		LookupUser: func(string) (User, error) { return User{}, ErrUnsupported },
		Unshare:    unsupported0,
		MountRAM:   func(string) error { return ErrUnsupported },
		Chown:      func(string, int, int) error { return ErrUnsupported },
		RemountRO:  func(string) error { return ErrUnsupported },
		Unmount:    func(string) error { return ErrUnsupported },
		Start: func(User, []string, []string) (func() (int, error), error) {
			return nil, ErrUnsupported
		},
		Move: func(string, string) error { return ErrUnsupported },
	}
}
