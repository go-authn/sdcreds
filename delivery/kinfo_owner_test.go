package delivery

import (
	"encoding/binary"
	"strings"
	"testing"
)

// The layout check of the three uid offsets: this process's own element must
// carry the ids getresuid(2) gives, the saved one included.
func TestCheckOwnIDs(t *testing.T) {
	e := elem(42, 1002, 1001)
	binary.NativeEndian.PutUint32(e[kinfoSvUIDOff:], 1003)
	buf := append(elem(7, 5, 5), e...)
	if err := checkOwnIDs(buf, 42, 1001, 1002, 1003); err != nil {
		t.Fatalf("a matching element: %v", err)
	}
	for name, c := range map[string]struct {
		buf          []byte
		pid, r, e, s int
	}{
		"wrong saved uid": {buf, 42, 1001, 1002, 1004},
		"saved offset shifted": {func() []byte {
			x := elem(42, 1002, 1001)
			binary.NativeEndian.PutUint32(x[kinfoSvUIDOff+4:], 1003)
			return x
		}(), 42, 1001, 1002, 1003},
		"wrong real uid":      {buf, 42, 9, 1002, 1003},
		"wrong effective uid": {buf, 42, 1001, 9, 1003},
		"pid not listed":      {buf, 43, 1001, 1002, 1003},
		"not a whole element": {append(buf, 0), 42, 1001, 1002, 1003},
	} {
		err := checkOwnIDs(c.buf, c.pid, c.r, c.e, c.s)
		if err == nil || !strings.Contains(err.Error(), "kinfo_proc") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
