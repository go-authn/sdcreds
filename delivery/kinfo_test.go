package delivery

import (
	"encoding/binary"
	"strings"
	"testing"
)

func elem(pid int32, uid, ruid uint32) []byte {
	e := make([]byte, kinfoSize)
	binary.NativeEndian.PutUint32(e[kinfoPidOff:], uint32(pid))
	binary.NativeEndian.PutUint32(e[kinfoUIDOff:], uid)
	binary.NativeEndian.PutUint32(e[kinfoRUIDOf:], ruid)
	return e
}

// The layout constants are the ones derived from sys/sys/sysctl.h (see kinfo.go).
func TestKinfoLayoutConstants(t *testing.T) {
	if kinfoSize != 648 || kinfoPidOff != 108 || kinfoUIDOff != 128 || kinfoRUIDOf != 132 ||
		kinfoStatOff != 304 || kinfoStartOff != 408 || kinfoPSFlagsOff != 560 {
		t.Fatalf("%d %d %d %d %d %d %d", kinfoSize, kinfoPidOff, kinfoUIDOff, kinfoRUIDOf, kinfoStatOff, kinfoStartOff, kinfoPSFlagsOff)
	}
}

func TestParseKinfo(t *testing.T) {
	buf := append(elem(10, 5000, 6000), elem(11, 5000, 6000)...)
	got, err := parseKinfo(buf, kernProcUID, 5000)
	if err != nil || len(got) != 2 || got[0].pid != 10 || got[1].pid != 11 {
		t.Fatalf("by effective uid: %v %v", got, err)
	}
	got, err = parseKinfo(buf, kernProcRUID, 6000)
	if err != nil || len(got) != 2 || got[0].pid != 10 {
		t.Fatalf("by real uid: %v %v", got, err)
	}
	if got, err := parseKinfo(nil, kernProcUID, 5000); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	// The kernel's own process (pid 0) is in the table of uid 0 on OpenBSD
	// (seen on 7.9 and 8.0); it is not a target.
	got, err = parseKinfo(append(elem(0, 0, 0), elem(7, 0, 0)...), kernProcUID, 0)
	if err != nil || len(got) != 1 || got[0].pid != 7 {
		t.Fatalf("pid 0: %v %v", got, err)
	}
}

// T2: a zombie is not listed; the starting time is read.
func TestParseKinfoZombiesAndStart(t *testing.T) {
	live := elem(10, 5000, 5000)
	binary.NativeEndian.PutUint64(live[kinfoStartOff:], 7)
	binary.NativeEndian.PutUint32(live[kinfoStartOff+8:], 5)
	byStat := func(stat int8) []byte { e := elem(11, 5000, 5000); e[kinfoStatOff] = byte(stat); return e }
	byFlags := elem(12, 5000, 5000)
	binary.NativeEndian.PutUint32(byFlags[kinfoPSFlagsOff:], psZombie|0x1)
	buf := append(append(append(append(live, byStat(sZomb)...), byStat(sDead)...), byFlags...), byStat(2)...)
	got, err := parseKinfo(buf, kernProcUID, 5000)
	if err != nil || len(got) != 2 || got[0] != (proc{pid: 10, start: 7_000_005}) || got[1].pid != 11 {
		t.Fatalf("%v %v", got, err)
	}
}

func TestParseKinfoRefusesAWrongLayout(t *testing.T) {
	for name, c := range map[string]struct {
		buf     []byte
		op, uid int
	}{
		"not a whole element":        {append(elem(10, 5000, 5000), 0), kernProcUID, 5000},
		"an element of another uid":  {append(elem(10, 5000, 5000), elem(11, 7, 7)...), kernProcUID, 5000},
		"the wrong uid field (eff)":  {elem(10, 5000, 6000), kernProcUID, 6000},
		"the wrong uid field (real)": {elem(10, 5000, 6000), kernProcRUID, 5000},
		"a negative pid":             {elem(-4, 5000, 5000), kernProcUID, 5000},
		"pid 0 of a target (T1)":     {elem(0, 5000, 5000), kernProcUID, 5000},
	} {
		got, err := parseKinfo(c.buf, c.op, c.uid)
		if err == nil || got != nil || !strings.Contains(err.Error(), "kinfo_proc") {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
}
