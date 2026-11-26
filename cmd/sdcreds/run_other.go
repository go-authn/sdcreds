//go:build !unix

package main

import "errors"

func canExecAs(string, int, int, []int) error { return errors.New("not supported on this system") }
