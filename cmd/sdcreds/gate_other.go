//go:build !unix

package main

import "github.com/spf13/cobra"

func addHelperCmds(*cobra.Command) {}
