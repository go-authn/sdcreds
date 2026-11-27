package delivery

import (
	"encoding/binary"
	"fmt"
)

// struct kinfo_proc of OpenBSD, from sys/sys/sysctl.h of the RELEASES targeted:
// sys.tar.gz of 7.9 (sha256 c9ef2940...57f1) and of 8.0 (sha256 964b1aed...2aaf)
// from cdn.openbsd.org/pub/OpenBSD/<rel>/, each hash read from the release's
// SHA256.sig, whose signify signature was verified (Ed25519, against
// openbsd-79-base.pub and openbsd-80-base.pub from ftp.openbsd.org). The file
// is byte-identical in 7.9, 8.0 and openbsd/src master, so one layout serves
// both; a release that changes it is refused by the per-element check below.
// Lines 372-496 (the mirror has no OPENBSD_*_BASE tags), opened and read; the header says "new elements should only be
// added to the end of this structure so binary compatibility can be
// preserved", lines 360-362). KI_MAXCOMLEN is _MAXCOMLEN = 24 (sys/sys/syslimits.h
// line 83). Offsets, with 8-byte alignment:
//
//	  0  p_forw .. p_ru: twelve u_int64_t pointers (lines 373-385)   -> 96
//	 96  p_eflag, p_exitsig, p_flag: three int32 (387-393)           -> 108
//	108  p_pid   int32  (395)
//	112  p_ppid, 116 p_sid, 120 p__pgid, 124 p_tpgid (396-400)
//	128  p_uid   uint32 (402, effective)
//	132  p_ruid  uint32 (403, real)
//	144 p_groups[KI_NGROUPS=16] (409: sysctl.h:364) -> 208 ... 304 p_stat int8 (447)
//	408 p_ustart_sec uint64, 416 p_ustart_usec uint32 (starting time, 462-463)
//	560 p_psflags uint32 (477), PS_ZOMBIE 0x00040000 (sys/sys/proc.h:316 in 8.0, 315 in 7.9)
//	...  the last field, p_name[KI_MAXCOMLEN] (495), ends at 648
//
// The offsets past 144 were summed by hand from the declaration (a layout that is
// off would show as live processes read as zombies, which checkProcLayout
// refuses at start: this very process, running, must be listed).
//
// The sizes were not trusted: the kernel is asked for elements of kinfoSize and
// every element read is checked against the uid that was asked for (a table
// read at the wrong stride shows itself as an element of another uid), so a
// layout that is not this one refuses instead of killing a guessed pid.
const (
	kinfoSize   = 648
	kinfoPidOff = 12*8 + 3*4
	kinfoUIDOff = kinfoPidOff + 5*4
	kinfoRUIDOf = kinfoUIDOff + 4

	kinfoStatOff    = 304 // p_stat, int8
	kinfoStartOff   = 408 // p_ustart_sec, uint64; p_ustart_usec uint32 follows
	kinfoPSFlagsOff = 560 // p_psflags, uint32
	// p_acflag (uint32) follows at 564, then p_svuid (uint32, "saved user id") and
	// p_svgid: consecutive in sys/sys/sysctl.h (lines 483-486 of master).
	kinfoSvUIDOff = kinfoPSFlagsOff + 2*4

	psZombie = 0x00040000 // PS_ZOMBIE
	sZomb    = 5          // SZOMB
	sDead    = 6          // SDEAD
)

// proc is one process of the table: its pid and its starting time, which tells a
// process from the one that took its pid later.
type proc struct {
	pid   int
	start uint64
}

// kinfo selectors of sysctl kern.proc, sys/sys/sysctl.h KERN_PROC_*.
const (
	kernProcUID  = 5 // KERN_PROC_UID: by effective uid
	kernProcRUID = 6 // KERN_PROC_RUID: by real uid
	// kernProcAll is KERN_PROC_ALL (sysctl.2: argument "None"): every process. The
	// kernel has no selector by SAVED uid, so those are found by reading them all.
	kernProcAll = 0
)

// parseKinfoAll reads a KERN_PROC_ALL answer and returns the live processes whose
// real, effective or saved uid is uid. Elements of other users are skipped (the
// table is not selected by uid); a buffer that is not a whole number of elements
// or a negative pid is the wrong layout and an error.
func parseKinfoAll(buf []byte, uid int) ([]proc, error) {
	if len(buf)%kinfoSize != 0 {
		return nil, fmt.Errorf("delivery: the process table is %d bytes, not a multiple of %d: struct kinfo_proc is not the one expected", len(buf), kinfoSize)
	}
	n := len(buf) / kinfoSize
	var pids []proc
	for i := 0; i < n; i++ {
		e := buf[i*kinfoSize : (i+1)*kinfoSize]
		pid := int(int32(binary.NativeEndian.Uint32(e[kinfoPidOff:])))
		if pid < 0 {
			return nil, fmt.Errorf("delivery: element %d of the process table has pid %d: struct kinfo_proc is not the one expected", i, pid)
		}
		if pid == 0 {
			continue // the kernel's own process
		}
		holds := false
		for _, off := range []int{kinfoUIDOff, kinfoRUIDOf, kinfoSvUIDOff} {
			if int(binary.NativeEndian.Uint32(e[off:])) == uid {
				holds = true
			}
		}
		if !holds {
			continue
		}
		stat := int8(e[kinfoStatOff])
		if stat == sZomb || stat == sDead || binary.NativeEndian.Uint32(e[kinfoPSFlagsOff:])&psZombie != 0 {
			continue
		}
		start := binary.NativeEndian.Uint64(e[kinfoStartOff:])*1_000_000 + uint64(binary.NativeEndian.Uint32(e[kinfoStartOff+8:]))
		pids = append(pids, proc{pid: pid, start: start})
	}
	return pids, nil
}

// checkOwnIDs reads the element of pid in a KERN_PROC_ALL answer and checks its
// real, effective and saved uids against the ones the caller got from
// getresuid(2). It is the layout check of the three uid offsets, including the
// saved one that parseKinfoAll uses and no selector of the kernel confirms. The
// limit, stated: when the three of the caller are equal (root: 0/0/0) a wrong
// offset that reads another zero is not seen; the OpenBSD lane tests the saved
// offset with a process whose three uids all differ.
func checkOwnIDs(buf []byte, pid, ruid, euid, svuid int) error {
	if len(buf)%kinfoSize != 0 {
		return fmt.Errorf("delivery: the process table is %d bytes, not a multiple of %d: struct kinfo_proc is not the one expected", len(buf), kinfoSize)
	}
	for i := 0; i < len(buf)/kinfoSize; i++ {
		e := buf[i*kinfoSize : (i+1)*kinfoSize]
		if int(int32(binary.NativeEndian.Uint32(e[kinfoPidOff:]))) != pid {
			continue
		}
		got := [3]int{int(binary.NativeEndian.Uint32(e[kinfoRUIDOf:])), int(binary.NativeEndian.Uint32(e[kinfoUIDOff:])), int(binary.NativeEndian.Uint32(e[kinfoSvUIDOff:]))}
		if got != [3]int{ruid, euid, svuid} {
			return fmt.Errorf("delivery: the process table lists this process with real/effective/saved uids %v, getresuid says %d/%d/%d: struct kinfo_proc is not the one expected", got, ruid, euid, svuid)
		}
		return nil
	}
	return fmt.Errorf("delivery: the process table does not list this process (pid %d): struct kinfo_proc is not the one expected", pid)
}

// parseKinfo reads the pids of a kern.proc answer of op for uid. Any element
// whose uid does not match the selector, whose pid is not positive, or a buffer
// that is not a whole number of elements, is an error: the layout is not the
// one this was written for.
func parseKinfo(buf []byte, op, uid int) ([]proc, error) {
	if len(buf)%kinfoSize != 0 {
		return nil, fmt.Errorf("delivery: the process table is %d bytes, not a multiple of %d: struct kinfo_proc is not the one expected", len(buf), kinfoSize)
	}
	off := kinfoUIDOff
	if op == kernProcRUID {
		off = kinfoRUIDOf
	}
	n := len(buf) / kinfoSize
	pids := make([]proc, 0, n)
	for i := 0; i < n; i++ {
		e := buf[i*kinfoSize : (i+1)*kinfoSize]
		pid := int(int32(binary.NativeEndian.Uint32(e[kinfoPidOff:])))
		got := int(binary.NativeEndian.Uint32(e[off:]))
		if pid < 0 || got != uid {
			return nil, fmt.Errorf("delivery: element %d of the process table has pid %d and uid %d, asked for uid %d (bytes 96-143: %x): struct kinfo_proc is not the one expected", i, pid, got, uid, e[96:144])
		}
		if pid == 0 {
			if uid != 0 {
				// The kernel's own process has uid 0 and is never a target: a pid 0
				// under another uid means the pid offset is wrong.
				return nil, fmt.Errorf("delivery: element %d of the process table has pid 0 and uid %d: struct kinfo_proc is not the one expected", i, got)
			}
			continue // the kernel's own process (pid 0, uid 0): listed by the table, never a target
		}
		stat := int8(e[kinfoStatOff])
		if stat == sZomb || stat == sDead || binary.NativeEndian.Uint32(e[kinfoPSFlagsOff:])&psZombie != 0 {
			continue // dead, waiting to be reaped: nothing to signal
		}
		start := binary.NativeEndian.Uint64(e[kinfoStartOff:])*1_000_000 + uint64(binary.NativeEndian.Uint32(e[kinfoStartOff+8:]))
		pids = append(pids, proc{pid: pid, start: start})
	}
	return pids, nil
}
