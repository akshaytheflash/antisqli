// Package cli implements the sqli command line interface.
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/akshaytheflash/antisqli/internal/ui"
	"github.com/akshaytheflash/antisqli/internal/version"
)

// Run is the CLI entry point. It returns a process exit code.
func Run(args []string) int {
	// Resolve presentation flags before any output is produced.
	color := os.Getenv("NO_COLOR") == "" && ui.IsTTY(os.Stdout) && !hasFlag(args, "--no-color")
	quiet := hasFlag(args, "-q") || hasFlag(args, "--quiet")
	verbose := hasFlag(args, "-v") || hasFlag(args, "--verbose")
	u := ui.New(ui.Options{Color: color, Quiet: quiet, Verbose: verbose})

	if len(args) == 0 {
		u.Banner(version.Name, version.Tagline, version.String())
		printRootHelp(u)
		return 0
	}

	if hasFlag(args, "-V") || hasFlag(args, "--version") {
		fmt.Println(version.Full())
		return 0
	}
	if hasFlag(args, "-h") || hasFlag(args, "--help") {
		printRootHelp(u)
		return 0
	}

	command := args[0]
	rest := args[1:]
	if strings.HasPrefix(command, "-") {
		command = "scan"
		rest = args
	}

	switch command {
	case "scan":
		return runScan(u, rest, false)
	case "crawl":
		return runScan(u, rest, true)
	case "payloads":
		return runPayloads(u, rest)
	case "tampers":
		return runTampers(u, rest)
	case "config":
		return runConfig(u, rest)
	case "version":
		fmt.Println(version.Full())
		return 0
	case "help":
		if len(rest) > 0 {
			return runHelp(u, rest[0])
		}
		printRootHelp(u)
		return 0
	default:
		u.Error("unknown command %q", command)
		u.Printf("Run %s to see available commands.", u.Cyan("sqli help"))
		return 2
	}
}

func runHelp(u *ui.UI, topic string) int {
	switch topic {
	case "scan", "crawl":
		printScanHelp(u)
	case "payloads":
		printPayloadHelp(u)
	case "config":
		printConfigHelp(u)
	default:
		printRootHelp(u)
	}
	return 0
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}
