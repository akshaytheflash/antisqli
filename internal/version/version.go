// Package version exposes build metadata for the sqli binary.
package version

import (
	"fmt"
	"runtime"
)

// These are overridden at build time via -ldflags "-X ...".
var (
	Version = "1.0.0"
	Commit  = "dev"
	Date    = "unknown"
)

// Name is the canonical tool name.
const Name = "sqli"

// Tagline is the one-line description used in banners and help output.
const Tagline = "SQL injection assessment toolkit"

// String returns a compact human readable version string.
func String() string {
	if Commit == "" || Commit == "dev" {
		return Version
	}
	if len(Commit) > 7 {
		Commit = Commit[:7]
	}
	return fmt.Sprintf("%s (%s)", Version, Commit)
}

// Full returns version, commit, build date and runtime information.
func Full() string {
	return fmt.Sprintf("%s %s built %s · %s %s/%s",
		Name, String(), Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
