//go:build !linux

package main

// hardenOS has nothing to do off Linux: s6-run needs Linux, and decrypt there
// keeps the traceback setting only.
func hardenOS() {}
