package tfa

import (
	"fmt"
	"runtime"
)

var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

func PrintBanner() {
	banner := `
============================================================
Beagle Gateway Forward Auth
------------------------------------------------------------
Version:    %s
Git Commit: %s
Build Date: %s
Go Version: %s
============================================================
`
	fmt.Printf(banner, Version, GitCommit, BuildDate, runtime.Version())
}
