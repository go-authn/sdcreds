package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A release that failed must not leave the run looking successful (R7).
func TestReleaseExit(t *testing.T) {
	boom := errors.New("survivors")
	for _, c := range []struct {
		err  error
		code int
		want int
		say  bool
	}{
		{nil, 0, 0, false},
		{nil, 3, 3, false},
		{boom, 0, exitReleaseFailed, true},
		// The program failed AND the release did: the survivor is not hidden.
		{boom, 3, exitReleaseFailed, true},
		{boom, 125, exitReleaseFailed, true},
		{boom, 143, exitReleaseFailed, true},
	} {
		var w bytes.Buffer
		if got := releaseExit(&w, c.err, c.code); got != c.want {
			t.Errorf("releaseExit(%v, %d) = %d, want %d", c.err, c.code, got, c.want)
		}
		if said := strings.Contains(w.String(), "survivors"); said != c.say {
			t.Errorf("releaseExit(%v, %d) printed %q", c.err, c.code, w.String())
		}
	}
	if exitReleaseFailed == 0 {
		t.Fatal("the failure status is zero")
	}
}
