//go:build !unix

package main

import "errors"

var errNoTrust = errors.New("key files named on the command line are not supported on this system")

func checkTrusted(string) error { return errNoTrust }

func readTrustedMachineID(string) ([16]byte, error) { return [16]byte{}, errNoTrust }
