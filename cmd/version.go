package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var (
	// Version info, can be overridden via ldflags: -X github.com/efekrbas/iso-guard/cmd.Version=v1.0.0
	Version   = "v0.1.0"
	GitCommit = "development"
	BuildDate = "2026-10-12"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version, build and runtime information of iso-guard",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("iso-guard %s\n", Version)
		fmt.Printf("  Commit     : %s\n", GitCommit)
		fmt.Printf("  Build Date : %s\n", BuildDate)
		fmt.Printf("  Go Version : %s\n", runtime.Version())
		fmt.Printf("  OS/Arch    : %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
