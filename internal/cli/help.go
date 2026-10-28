package cli

import (
	"fmt"

	"github.com/akshaytheflash/antisqli/internal/ui"
)

func printRootHelp(u *ui.UI) {
	u.Printf("%s %s", u.Bold("USAGE"), u.Dim("- one command, no config required"))
	u.Printf("  sqli scan   -u <url> [flags]")
	u.Printf("  sqli crawl  -u <url> [flags]")
	u.Printf("  sqli scan   -r <request-file> [flags]")
	u.Printf("  sqli scan   --curl %q [flags]", "curl 'https://...'")
	u.Printf("  sqli scan   -l urls.txt [flags]")
	u.Printf("  sqli <command> --help")

	u.Printf("\n%s", u.Bold("COMMANDS"))
	table := [][2]string{
		{"scan", "assess a URL, raw request, curl command or URL list"},
		{"crawl", "discover links and forms, then scan every parameter"},
		{"payloads", "show the payload library and backend coverage"},
		{"tampers", "list tamper scripts used for WAF evasion"},
		{"config", "show, initialize or locate the configuration"},
		{"version", "print build information"},
		{"help", "show help for a command"},
	}
	for _, row := range table {
		u.Printf("  %-10s %s", u.Cyan(row[0]), row[1])
	}

	u.Printf("\n%s", u.Bold("EXAMPLES"))
	examples := [][2]string{
		{"Quick scan", "sqli scan -u \"https://target/item?id=1\" --authorized"},
		{"From Burp", "sqli scan -r request.txt --authorized"},
		{"Full crawl", "sqli crawl -u https://target --depth 2 --authorized"},
		{"Deep scan", "sqli scan -u \"...?id=1\" --level 3 --risk 2 --technique all"},
		{"JSON report", "sqli scan -u \"...?id=1\" --json -o report.json"},
		{"Through proxy", "sqli scan -u \"...\" --proxy http://127.0.0.1:8080 -k"},
	}
	for _, ex := range examples {
		u.Printf("  %s %s", u.Dim(fmt.Sprintf("%-12s", ex[0])), u.Green(ex[1]))
	}

	u.Printf("\n%s", u.Bold("SAFETY"))
	u.Printf("  sqli sends active probes and requires %s.", u.Cyan("--authorized"))
	u.Printf("  Only test systems you own or have written permission to assess.")
	u.Printf("  All payloads are read-only: no INSERT, UPDATE, DELETE or DDL.")

	u.Printf("\n%s", u.Bold("EXIT CODES"))
	u.Printf("  0 no findings   ·   1 findings   ·   2 error")
	u.Printf("\n  %s\n", u.Dim("Documentation: README.md · License: MIT"))
}

func printScanHelp(u *ui.UI) {
	u.Printf("%s - test a request for SQL injection", u.Bold("sqli scan"))
	u.Printf("\n%s", u.Bold("USAGE"))
	u.Printf("  sqli scan -u <url> [flags]")
	u.Printf("  sqli scan -r <request-file> [flags]")
	u.Printf("  sqli scan --curl %q [flags]", "curl '...'")
	u.Printf("  sqli crawl -u <url> [flags]")

	u.Printf("\n%s", u.Bold("TARGET"))
	flags(u, [][3]string{
		{"-u, --url", "URL to scan (https assumed when the scheme is omitted)", ""},
		{"-r, --request", "raw HTTP request file (Burp Suite / devtools export)", ""},
		{"--curl", "curl command to replay", ""},
		{"-l, --list", "file with one URL per line (- for stdin)", ""},
		{"--scheme", "scheme for raw requests: https (default) or http", ""},
	})

	u.Printf("\n%s", u.Bold("REQUEST"))
	flags(u, [][3]string{
		{"-X, --method", "HTTP method override", ""},
		{"-d, --data", "request body (form encoded or JSON)", ""},
		{"-H, --header", "extra header, repeatable (\"Name: value\")", ""},
		{"-b, --cookie", "Cookie header value", ""},
		{"-A, --user-agent", "User-Agent override", ""},
		{"-p, --param", "test only these parameters (comma separated)", ""},
		{"--skip", "parameters to ignore", ""},
		{"--header-point", "treat this header as injectable, repeatable", ""},
		{"--path-segments", "test path segments (level 2+)", ""},
	})

	u.Printf("\n%s", u.Bold("DETECTION"))
	flags(u, [][3]string{
		{"--technique", "error,boolean,time,union,all (default error,boolean,time)", ""},
		{"--level", "payload coverage 1-3 (default 1)", ""},
		{"--risk", "payload risk 1-3 (default 1)", ""},
		{"--dbms", "assume backend: mysql,postgres,mssql,oracle,sqlite", ""},
		{"--tamper", "tamper script, repeatable (see sqli tampers)", ""},
		{"--time-delay", "seconds to sleep in time-based tests (default 5)", ""},
		{"--samples", "baseline and timing samples (default 3)", ""},
		{"--thorough", "run every technique on every parameter", ""},
		{"--crawl", "crawl the target before scanning", ""},
		{"--depth", "crawl depth (default 2)", ""},
		{"--max-pages", "crawl page limit (default 50)", ""},
		{"--same-host", "stay on the seed host (default true)", ""},
		{"--respect-robots", "honor robots.txt", ""},
		{"--exclude", "skip URLs containing this substring, repeatable", ""},
	})

	u.Printf("\n%s", u.Bold("PERFORMANCE & NETWORK"))
	flags(u, [][3]string{
		{"--concurrency", "parallel workers (default 8)", ""},
		{"--timeout", "per-request timeout in seconds (default 15)", ""},
		{"--delay", "delay between requests in ms", ""},
		{"--rate", "maximum requests per second (0 = unlimited)", ""},
		{"--retries", "retries for transient failures (default 2)", ""},
		{"--max-requests", "hard request budget (default 5000)", ""},
		{"--proxy", "http, https or socks5 proxy URL", ""},
		{"-k, --insecure", "skip TLS certificate verification", ""},
		{"--no-redirect", "do not follow redirects", ""},
	})

	u.Printf("\n%s", u.Bold("OUTPUT"))
	flags(u, [][3]string{
		{"-o, --output", "write report to .json or .md (format inferred)", ""},
		{"--format", "text, json or markdown", ""},
		{"--json", "print JSON to stdout", ""},
		{"--list-points", "list injectable parameters and exit", ""},
		{"-q, --quiet", "suppress banner and progress", ""},
		{"-v, --verbose", "debug output", ""},
		{"--no-color", "disable ANSI colors", ""},
	})

	u.Printf("\n%s", u.Bold("SAFETY"))
	flags(u, [][3]string{
		{"--authorized", "confirm you have permission to test the target", ""},
		{"--config", "configuration file path", ""},
	})

	u.Printf("\n%s", u.Bold("EXAMPLES"))
	u.Printf("  sqli scan -u \"https://target/item?id=1\" --authorized")
	u.Printf("  sqli scan -r request.txt --authorized -o findings.md")
	u.Printf("  sqli crawl -u https://target --depth 2 --level 2 --authorized")
	u.Printf("  sqli scan -u \"https://target/api?q=x\" -H \"Authorization: Bearer ...\" --json")
}

func printPayloadHelp(u *ui.UI) {
	u.Printf("%s - payload library overview", u.Bold("sqli payloads"))
	u.Printf("\nShows technique coverage, backend support and tamper scripts.")
	u.Printf("Run %s for the tamper table.\n", u.Cyan("sqli tampers"))
}

func printConfigHelp(u *ui.UI) {
	u.Printf("%s - configuration", u.Bold("sqli config"))
	u.Printf("\n%s", u.Bold("USAGE"))
	u.Printf("  sqli config            show the effective configuration")
	u.Printf("  sqli config init       write a default config file")
	u.Printf("  sqli config init --force")
	u.Printf("  sqli config path       print the config file path")
	u.Printf("\nSet %s to use a different file.", u.Cyan("SQLI_CONFIG"))
}

func flags(u *ui.UI, rows [][3]string) {
	for _, row := range rows {
		u.Printf("  %s  %s", u.Cyan(fmt.Sprintf("%-18s", row[0])), row[1])
	}
}
