package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "LMD-NG Print Version Number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Linux Malware Detect Next Generation (LMD-NG) v%s~%s\n", version, commit)
			fmt.Println("By Dimas Restu H <drh.dimasrestu@gmail.com>")
		},
	}
}
