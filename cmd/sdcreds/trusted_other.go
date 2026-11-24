//go:build !unix

package main

import (
	"errors"
	"os"
)

var errNoTrust = errors.New("key files named on the command line are not supported on this system")

func openTrusted(string) (*os.File, error) { return nil, errNoTrust }

func readTrustedMachineID(string) ([16]byte, error) { return [16]byte{}, errNoTrust }
