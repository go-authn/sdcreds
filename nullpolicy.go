package sdcreds

import (
	"fmt"
	"strings"
)

// BootPolicy is systemd.credentials_boot_policy= (cu.h:69-76).
type BootPolicy int

// The four policies; the default is BootRelaxed (cu.c:1274).
const (
	BootStrict BootPolicy = iota
	BootTOFU
	BootRelaxed
	BootOff
)

// ParseBootPolicy parses strict, tofu, relaxed or off.
func ParseBootPolicy(s string) (BootPolicy, bool) {
	switch s {
	case "strict":
		return BootStrict, true
	case "tofu":
		return BootTOFU, true
	case "relaxed":
		return BootRelaxed, true
	case "off":
		return BootOff, true
	}
	return BootRelaxed, false
}

// AcceptsNull is credential_boot_policy_accepts_null (cu.c:391-413).
func (p BootPolicy) AcceptsNull(firstBoot, haveTPM2, secureBoot bool) bool {
	switch p {
	case BootStrict:
		return false
	case BootTOFU:
		return firstBoot || !haveTPM2
	case BootRelaxed:
		return !secureBoot || !haveTPM2
	case BootOff:
		return true
	}
	return false
}

// PolicyFromCmdline finds systemd.credentials_boot_policy= (or the rd. prefixed
// form) in a kernel command line; an absent or invalid value is BootRelaxed
// (cu.c:1273-1284).
func PolicyFromCmdline(cmdline string) BootPolicy {
	pol := BootRelaxed
	for _, f := range strings.Fields(cmdline) {
		for _, pre := range []string{"systemd.credentials_boot_policy=", "rd.systemd.credentials_boot_policy="} {
			if v, ok := strings.CutPrefix(f, pre); ok {
				if p, ok := ParseBootPolicy(v); ok {
					pol = p
				}
			}
		}
	}
	return pol
}

// NullPolicyFor returns a DecryptOptions.NullPolicy that applies policy to the
// given system state (check_null_key_policy, cu.c:1289-1332).
func NullPolicyFor(policy BootPolicy, firstBoot, haveTPM2, secureBoot bool) func() error {
	return func() error {
		if !policy.AcceptsNull(firstBoot, haveTPM2, secureBoot) {
			return fmt.Errorf("%w: boot policy refuses it here (TPM2=%v, SecureBoot=%v, first boot=%v)",
				ErrNullRefused, haveTPM2, secureBoot, firstBoot)
		}
		return nil
	}
}

// SystemNullPolicy reads the kernel command line, the EFI SecureBoot variable
// and the TPM2 hints of this machine, as systemd does. Off Linux it accepts.
// It is a variable so that tests and other platforms can replace it.
var SystemNullPolicy = systemNullPolicy
