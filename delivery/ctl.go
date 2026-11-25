package delivery

import (
	"bufio"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The control socket between the owner and the helper carries one line per
// message, never a secret:
//
//	helper -> owner   "ready"            the mount is up
//	                  "ok"               the last request was done
//	                  "fail TEXT"        the helper could not do its job
//	owner  -> helper  "pgid N"           kill process group N if the owner dies
//	                  "release"          unmount, zero, exit
//
// A line is at most maxCtlLine bytes, printable ASCII.
const maxCtlLine = 256

// CtlKind is the kind of a control message.
type CtlKind int

const (
	CtlReady CtlKind = iota + 1
	CtlOK
	CtlFail
	CtlPGID
	CtlRelease
)

// Ctl is one parsed control message.
type Ctl struct {
	Kind CtlKind
	PGID int    // CtlPGID
	Text string // CtlFail
}

// ErrCtl is a malformed control line.
var ErrCtl = errors.New("delivery: malformed control message")

// ParseCtl parses one line (without its newline). It accepts exactly the
// messages above: no extra space, no sign, no leading zero, a group number from
// 2 to 2^31-1 (kill(-1) and kill(0) are not process groups).
func ParseCtl(line string) (Ctl, error) {
	if len(line) > maxCtlLine {
		return Ctl{}, fmt.Errorf("%w: too long", ErrCtl)
	}
	for i := 0; i < len(line); i++ {
		if line[i] < ' ' || line[i] >= 127 {
			return Ctl{}, fmt.Errorf("%w: not printable ASCII", ErrCtl)
		}
	}
	switch {
	case line == "ready":
		return Ctl{Kind: CtlReady}, nil
	case line == "ok":
		return Ctl{Kind: CtlOK}, nil
	case line == "release":
		return Ctl{Kind: CtlRelease}, nil
	case strings.HasPrefix(line, "fail "):
		return Ctl{Kind: CtlFail, Text: line[len("fail "):]}, nil
	case strings.HasPrefix(line, "pgid "):
		s := line[len("pgid "):]
		if s == "" || s[0] == '0' || len(s) > 10 {
			return Ctl{}, fmt.Errorf("%w: bad group", ErrCtl)
		}
		// ParseUint takes digits only: no sign, no space, no underscore.
		n, err := strconv.ParseUint(s, 10, 31)
		if err != nil || n < 2 {
			return Ctl{}, fmt.Errorf("%w: bad group", ErrCtl)
		}
		return Ctl{Kind: CtlPGID, PGID: int(n)}, nil
	}
	return Ctl{}, fmt.Errorf("%w: unknown message", ErrCtl)
}

// String formats a message the way ParseCtl reads it (without the newline).
func (c Ctl) String() string {
	switch c.Kind {
	case CtlReady:
		return "ready"
	case CtlOK:
		return "ok"
	case CtlRelease:
		return "release"
	case CtlPGID:
		return "pgid " + strconv.Itoa(c.PGID)
	case CtlFail:
		return "fail " + sanitize(c.Text)
	}
	return ""
}

// sanitize keeps a text printable and short enough for one line.
func sanitize(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < maxCtlLine-8; i++ {
		if s[i] >= ' ' && s[i] < 127 {
			b = append(b, s[i])
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}

// readCtl reads one line of at most maxCtlLine bytes; a longer line is an
// error and nothing more is read of it.
func readCtl(r *bufio.Reader) (Ctl, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxCtlLine+1 {
			return Ctl{}, fmt.Errorf("%w: too long", ErrCtl)
		}
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return Ctl{}, err
		}
	}
	return ParseCtl(strings.TrimSuffix(string(line), "\n"))
}
