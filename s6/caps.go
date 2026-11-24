package s6

import (
	"fmt"
	"slices"
	"strings"
)

// Cap is a Linux capability number (linux/capability.h).
type Cap int

// The capabilities s6-run may be asked to keep for the service (--keep-cap).
// This is an allowlist, and every entry is here for the same two reasons: it
// is not root-equivalent, and holding it lets the service neither read or write
// the credential tmpfs (that needs CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH,
// CAP_FOWNER, CAP_CHOWN or CAP_SYS_ADMIN, none of which is listed) nor signal,
// ptrace or otherwise reach the root s6-run (CAP_KILL, CAP_SYS_PTRACE and
// CAP_SETUID are not listed either; a signal to another uid needs CAP_KILL).
const (
	// CapNetBindService: bind a port below 1024. Network only.
	CapNetBindService Cap = 10
	// CapNetBroadcast: socket broadcasting and multicast listening. Network only.
	CapNetBroadcast Cap = 11
	// CapNetAdmin: interfaces, routes, firewall, tun devices (a VPN server). It
	// configures the network of the namespace and touches no file or process.
	CapNetAdmin Cap = 12
	// CapNetRaw: raw and packet sockets. Network only.
	CapNetRaw Cap = 13
	// CapIPCLock: mlock and SysV shared memory locking, so that key material in
	// the service stays out of swap. It exempts the service from RLIMIT_MEMLOCK
	// and from no file or process.
	CapIPCLock Cap = 14
	// CapWakeAlarm: arm alarm timers that wake the system. Time only.
	CapWakeAlarm Cap = 35
	// CapBlockSuspend: hold the system awake (wake locks, EPOLLWAKEUP). Power only.
	CapBlockSuspend Cap = 36
)

// keepAllowed is the allowlist in the order it is reported.
var keepAllowed = []Cap{
	CapNetAdmin, CapNetBindService, CapNetRaw, CapNetBroadcast, CapIPCLock, CapWakeAlarm, CapBlockSuspend,
}

// capNames are all the capabilities of linux/capability.h (Linux 6.x), by
// number, so that a known capability that is not allowed is told from a typo.
var capNames = [...]string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER", "CAP_FSETID",
	"CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP", "CAP_LINUX_IMMUTABLE",
	"CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST", "CAP_NET_ADMIN", "CAP_NET_RAW",
	"CAP_IPC_LOCK", "CAP_IPC_OWNER", "CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT",
	"CAP_SYS_PTRACE", "CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD", "CAP_LEASE",
	"CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP", "CAP_MAC_OVERRIDE",
	"CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ",
	"CAP_PERFMON", "CAP_BPF", "CAP_CHECKPOINT_RESTORE",
}

func (c Cap) String() string {
	if c >= 0 && int(c) < len(capNames) {
		return capNames[c]
	}
	return fmt.Sprintf("CAP_%d", int(c))
}

func allowlist() string {
	names := make([]string, len(keepAllowed))
	for i, c := range keepAllowed {
		names[i] = c.String()
	}
	return strings.Join(names, ", ")
}

// CheckKeepCaps refuses every capability that is not on the allowlist.
func CheckKeepCaps(keep []Cap) error {
	for _, c := range keep {
		if !slices.Contains(keepAllowed, c) {
			return fmt.Errorf("s6: capability %v may not be kept; the allowlist is %s", c, allowlist())
		}
	}
	return nil
}

// ParseKeepCaps turns the values of a repeatable, comma-separated --keep-cap
// into a sorted set without duplicates. The names are those of capabilities(7),
// written in full (CAP_NET_ADMIN). A name that is not a capability is an error,
// and so is one that is a capability but not on the allowlist; both errors
// name the allowlist. Nothing given is no capability kept.
func ParseKeepCaps(values []string) ([]Cap, error) {
	var out []Cap
	for _, v := range values {
		for _, name := range strings.Split(v, ",") {
			name = strings.ToUpper(strings.TrimSpace(name))
			i := slices.Index(capNames[:], name)
			if i < 0 {
				return nil, fmt.Errorf("s6: %q is not a capability; the allowlist is %s", name, allowlist())
			}
			out = append(out, Cap(i))
		}
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if err := CheckKeepCaps(out); err != nil {
		return nil, err
	}
	return out, nil
}
