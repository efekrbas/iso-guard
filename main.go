package main

import (
	"os"

	"github.com/efekrbas/iso-guard/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
