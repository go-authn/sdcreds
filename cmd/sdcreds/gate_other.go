//go:build !unix

package main

import "github.com/spf13/cobra"

func addHelperCmds(*cobra.Command) {}

// Off unix `run` is refused before these matter.
func checkPassEnv([]string) error { return nil }
func checkPassFDs([]int) error    { return nil }
