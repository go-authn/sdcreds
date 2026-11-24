package main

import "runtime/debug"

// hardenProcess keeps secrets out of core dumps, ptrace and crash traces. It is
// a variable so that the tests see it called; failure to lower a limit is not
// fatal, it only means the process keeps the default it was started with.
var hardenProcess = func() {
	debug.SetTraceback("none")
	hardenOS()
}
