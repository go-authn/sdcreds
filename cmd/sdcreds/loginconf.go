package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
)

// loginConfMax bounds what is read of login.conf(5).
const loginConfMax = 1 << 20

// loginConfPath is the file `run --class` is validated against.
var loginConfPath = "/etc/login.conf"

// ParseLoginClasses returns the class names (every alias of every entry) that
// a login.conf(5) file defines. An entry starts on a line that does not begin
// with white space or '#'; its names are the '|'-separated words before the
// first ':'; a backslash at the end of a line continues it. Only the names
// are read: the capabilities of a class are not interpreted (see
// the documentation of --class). Input over loginConfMax is refused.
func ParseLoginClasses(r io.Reader) ([]string, error) {
	data, err := io.ReadAll(io.LimitReader(r, loginConfMax+1))
	if err != nil {
		return nil, err
	}
	if len(data) > loginConfMax {
		return nil, fmt.Errorf("login.conf is longer than %d bytes", loginConfMax)
	}
	var names []string
	cont := false // the previous line ended with a backslash
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 4096), loginConfMax+1)
	for sc.Scan() {
		line := sc.Text()
		wasCont := cont
		cont = strings.HasSuffix(line, "\\")
		if wasCont || line == "" || line[0] == '#' || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		head, _, _ := strings.Cut(line, ":")
		head = strings.TrimSuffix(head, "\\")
		for _, n := range strings.Split(head, "|") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, bufio.ErrTooLong) {
		return nil, err
	}
	return names, nil
}
