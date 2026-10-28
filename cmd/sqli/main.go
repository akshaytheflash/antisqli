// Command sqli is a SQL injection assessment toolkit.
//
// It discovers injectable parameters, confirms them with error-based,
// boolean-based, time-based and UNION-based techniques, fingerprints the
// database, detects WAFs and produces terminal, JSON or Markdown reports.
package main

import (
	"os"

	"github.com/akshaytheflash/antisqli/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
