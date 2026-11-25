package delivery

import (
	"encoding/binary"
	"fmt"
)

// struct kinfo_proc of OpenBSD, from sys/sys/sysctl.h (openbsd/src, master,
// lines 372-496, opened and read; the header says "new elements should only be
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
//	...  the last field, p_name[KI_MAXCOMLEN] (495), ends at 648
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
)

// kinfo selectors of sysctl kern.proc, sys/sys/sysctl.h KERN_PROC_*.
const (
	kernProcUID  = 5 // KERN_PROC_UID: by effective uid
	kernProcRUID = 6 // KERN_PROC_RUID: by real uid
)

// parseKinfo reads the pids of a kern.proc answer of op for uid. Any element
// whose uid does not match the selector, whose pid is not positive, or a buffer
// that is not a whole number of elements, is an error: the layout is not the
// one this was written for.
func parseKinfo(buf []byte, op, uid int) ([]int, error) {
	if len(buf)%kinfoSize != 0 {
		return nil, fmt.Errorf("delivery: the process table is %d bytes, not a multiple of %d: struct kinfo_proc is not the one expected", len(buf), kinfoSize)
	}
	off := kinfoUIDOff
	if op == kernProcRUID {
		off = kinfoRUIDOf
	}
	n := len(buf) / kinfoSize
	pids := make([]int, 0, n)
	for i := 0; i < n; i++ {
		e := buf[i*kinfoSize : (i+1)*kinfoSize]
		pid := int(int32(binary.NativeEndian.Uint32(e[kinfoPidOff:])))
		got := int(binary.NativeEndian.Uint32(e[off:]))
		if pid <= 0 || got != uid {
			return nil, fmt.Errorf("delivery: element %d of the process table has pid %d and uid %d, asked for uid %d (bytes 96-143: %x): struct kinfo_proc is not the one expected", i, pid, got, uid, e[96:144])
		}
		pids = append(pids, pid)
	}
	return pids, nil
}
