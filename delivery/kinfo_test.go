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
	if kinfoSize != 648 || kinfoPidOff != 108 || kinfoUIDOff != 128 || kinfoRUIDOf != 132 {
		t.Fatalf("%d %d %d %d", kinfoSize, kinfoPidOff, kinfoUIDOff, kinfoRUIDOf)
	}
}

func TestParseKinfo(t *testing.T) {
	buf := append(elem(10, 5000, 6000), elem(11, 5000, 6000)...)
	got, err := parseKinfo(buf, kernProcUID, 5000)
	if err != nil || len(got) != 2 || got[0] != 10 || got[1] != 11 {
		t.Fatalf("by effective uid: %v %v", got, err)
	}
	got, err = parseKinfo(buf, kernProcRUID, 6000)
	if err != nil || len(got) != 2 || got[0] != 10 {
		t.Fatalf("by real uid: %v %v", got, err)
	}
	if got, err := parseKinfo(nil, kernProcUID, 5000); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
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
		"a zero pid":                 {elem(0, 5000, 5000), kernProcUID, 5000},
		"a negative pid":             {elem(-4, 5000, 5000), kernProcUID, 5000},
	} {
		got, err := parseKinfo(c.buf, c.op, c.uid)
		if err == nil || got != nil || !strings.Contains(err.Error(), "kinfo_proc") {
			t.Errorf("%s: %v %v", name, got, err)
		}
	}
}
