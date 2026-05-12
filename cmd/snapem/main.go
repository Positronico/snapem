package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/positronico/snapem/internal/cli"
	snaperr "github.com/positronico/snapem/internal/errors"
)

// Version information (set by ldflags during build)
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersionInfo(version, commit, date)

	err := cli.Execute()
	if err == nil {
		return
	}

	// rootCmd has SilenceErrors=true so cobra won't print; we own that
	// responsibility here. Match the exit code carried by the typed
	// SnapemError when there is one, fall back to 1 otherwise.
	fmt.Fprintln(os.Stderr, "Error:", err)

	var se *snaperr.SnapemError
	if errors.As(err, &se) {
		os.Exit(se.ExitCode())
	}
	os.Exit(1)
}
