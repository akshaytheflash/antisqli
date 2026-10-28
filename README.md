# sqli

A SQL injection assessment toolkit written in Go. It finds and confirms SQL
injection in web applications, fingerprints the database, detects web
application firewalls, and writes reports for developers. It is a single static
binary with no third-party dependencies.

```
$ sqli scan -u "https://example.com/product?id=1" --authorized

  ███████╗ ██████╗ ██╗     ██╗
  ██╔════╝██╔═══██╗██║     ██║
  ███████╗██║   ██║██║     ██║
  ╚════██║██║▄▄ ██║██║     ██║
  ███████║╚██████╔╝███████╗██║
  ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝
  sqli v1.0.0
  SQL injection assessment toolkit

──────────────────────────────────────────────────────────────
◆ Findings (1)
──────────────────────────────────────────────────────────────

   CRITICAL  query parameter "id" (1/1)
    Technique  error-based
    Backend    MySQL / MariaDB
    Confidence 98%
    Endpoint   GET https://example.com/product
    Payload    '
    Evidence   mysql error leaked version 8.0.32
```

## Features

- Error-based, boolean-based blind, time-based blind and UNION-based detection.
- Injection points in query strings, form bodies, JSON bodies, cookies,
  headers and path segments.
- Backend fingerprinting for MySQL/MariaDB, PostgreSQL, MSSQL, Oracle and
  SQLite, including version extraction where the backend leaks it.
- Baseline learning that masks volatile tokens such as CSRF nonces and
  timestamps before comparing responses.
- Timing checks use the median of repeated samples plus a zero-delay control
  request to reject network jitter.
- WAF detection for Cloudflare, Akamai, Imperva, Sucuri, ModSecurity, F5 and
  other common products.
- Input from URLs, raw HTTP requests (Burp Suite, browser devtools), curl
  commands, URL lists, or the built-in crawler.
- Twelve composable tamper scripts for filter and WAF evasion.
- Rate limiting, request jitter, retries, redirect control and a hard request
  budget.
- Terminal, JSON and Markdown reports with stable exit codes.

## Install

### From source

```bash
git clone https://github.com/akshaytheflash/antisqli.git
cd antisqli
make build            # produces bin/sqli
```

On native Windows use the PowerShell helper:

```powershell
git clone https://github.com/akshaytheflash/antisqli.git
cd antisqli
.\build.ps1 build     # produces bin\sqli.exe
```

Or with the Go toolchain directly:

```bash
go install github.com/akshaytheflash/antisqli/cmd/sqli@latest
```

Go 1.24 or newer is required. There are no third-party modules.

### Verify

```bash
sqli version
sqli payloads
```

## Quick start

```bash
# One parameter
sqli scan -u "https://example.com/item?id=1" --authorized

# A request exported from Burp Suite
sqli scan -r request.txt --authorized

# A curl command copied from browser devtools
sqli scan --curl "curl 'https://example.com/api?q=x' -H 'Authorization: Bearer ...'" --authorized

# Discover endpoints and forms, then scan every parameter
sqli crawl -u https://example.com --depth 2 --authorized

# Deeper coverage with WAF evasion and a JSON report
sqli scan -u "https://example.com/item?id=1" \
  --level 3 --risk 2 --technique all \
  --tamper space2comment,randomcase \
  --json -o report.json --authorized
```

### Local demo

The repository includes an intentionally vulnerable application for testing the
scanner without touching a real target.

```bash
go run ./cmd/vulnserver            # listens on 127.0.0.1:8099
sqli scan -u "http://127.0.0.1:8099/item?id=1" --authorized
```

## Commands

| Command | Purpose |
|---|---|
| `sqli scan` | assess a URL, raw request, curl command or URL list |
| `sqli crawl` | crawl links and forms, then scan every discovered parameter |
| `sqli payloads` | show payload coverage and backend support |
| `sqli tampers` | list tamper scripts |
| `sqli config` | show, initialize or locate the configuration |
| `sqli version` | print build metadata |
| `sqli help <cmd>` | detailed help for a command |

Run `sqli help scan` for the full flag reference.

## How it works

### Discovery

`sqli` builds a request template and enumerates every place a value can enter
the application:

- query string parameters
- `application/x-www-form-urlencoded` bodies
- JSON bodies, including nested objects and arrays
- cookies
- selected headers (`--header-point`, or common headers at `--level 3`)
- path segments (`--path-segments`, level 2 and above)

With `--crawl`, links and forms are followed breadth-first, bounded by depth,
page count and an exclusion list that avoids destructive GET links such as
`/logout` or `/delete`.

### Baseline learning

Each parameter is requested several times unchanged. The engine records the
stable token set of the page, the tokens that change between requests, and the
median response time with its median absolute deviation. Comparisons ignore the
volatile tokens, so dynamic pages do not cause false positives.

### Detection

**Error-based.** Sends syntax breakers and DBMS-specific extraction payloads,
then looks for database error signatures that were absent from the baseline.
When a backend is identified, a second payload reads the version from the error
message.

**Boolean-based blind.** Sends logically true and false payload pairs and
compares each response to the baseline using Jaccard similarity over token
trigrams, plus length and status checks. A candidate must survive a second
round before it is reported.

**Time-based blind.** Measures the baseline latency, then requires the injected
delay to be visible in the median of repeated samples. A zero-delay control
request shows that the delay came from the injected expression rather than the
network. Timing checks run serially so concurrent traffic cannot distort the
measurements.

**UNION-based.** Counts columns with `ORDER BY`, confirms with `UNION SELECT
NULL...`, reflects a unique marker to prove the result set is attacker
controlled, then reads the database version.

A parameter is reported once, with the first confirmed technique, unless
`--thorough` is set.

### Reporting

Findings include the parameter, location, endpoint, technique, backend,
confidence, the exact payload, evidence, and any leaked version or column
count. Severity is derived from the technique and the confidence score.

## Flag reference

### Target

| Flag | Description |
|---|---|
| `-u, --url` | target URL (https assumed when the scheme is omitted) |
| `-r, --request` | raw HTTP request file |
| `--curl` | curl command to replay |
| `-l, --list` | file with one URL per line (`-` for stdin) |
| `--scheme` | scheme for raw requests: `https` (default) or `http` |

### Request

| Flag | Description |
|---|---|
| `-X, --method` | HTTP method override |
| `-d, --data` | request body (form or JSON) |
| `-H, --header` | extra header, repeatable |
| `-b, --cookie` | Cookie header value |
| `-A, --user-agent` | User-Agent override |
| `-p, --param` | only test these parameters |
| `--skip` | parameters to ignore |
| `--header-point` | header to treat as injectable, repeatable |
| `--path-segments` | test path segments (level 2 and above) |

### Detection

| Flag | Description |
|---|---|
| `--technique` | `error,boolean,time,union` or `all` |
| `--level` | payload coverage 1 to 3 (default 1) |
| `--risk` | payload risk 1 to 3 (default 1) |
| `--dbms` | assume a backend instead of fingerprinting |
| `--tamper` | tamper script, repeatable |
| `--time-delay` | seconds to sleep in time-based tests |
| `--samples` | baseline and timing samples |
| `--thorough` | run every technique on every parameter |
| `--crawl` | crawl before scanning |
| `--depth`, `--max-pages` | crawl bounds |
| `--same-host`, `--respect-robots` | crawl scope and politeness |
| `--exclude` | skip URLs containing a substring |

### Performance and network

| Flag | Description |
|---|---|
| `--concurrency` | parallel workers (default 8) |
| `--timeout` | per-request timeout in seconds |
| `--delay`, `--rate` | spacing between requests |
| `--retries` | retries for transient failures |
| `--max-requests` | hard request budget (default 5000) |
| `--proxy` | `http`, `https` or `socks5` proxy |
| `-k, --insecure` | skip TLS verification |
| `--no-redirect` | do not follow redirects |

### Output

| Flag | Description |
|---|---|
| `-o, --output` | write a report; format inferred from `.json` or `.md` |
| `--format` | `text`, `json` or `markdown` |
| `--json` | print JSON to stdout |
| `--list-points` | show injectable parameters and exit |
| `-q, --quiet` | suppress banner and progress |
| `-v, --verbose` | debug output |
| `--no-color` | disable ANSI colors |

### Safety

| Flag | Description |
|---|---|
| `--authorized` | confirm permission to test the target |
| `--config` | configuration file path |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | scan completed, no findings |
| `1` | scan completed, findings confirmed |
| `2` | usage error, authorization refused, or scan failure |

## Configuration

Configuration lives in the platform config directory:

- Linux: `~/.config/sqli/config.json`
- macOS: `~/Library/Application Support/sqli/config.json`
- Windows: `%AppData%\sqli\config.json`

```bash
sqli config            # show effective settings
sqli config init       # write defaults
sqli config path       # print the path
```

```json
{
  "timeout_seconds": 15,
  "concurrency": 8,
  "delay_ms": 0,
  "rate_per_second": 0,
  "retries": 2,
  "time_samples": 3,
  "time_delay_seconds": 5,
  "level": 1,
  "risk": 1,
  "user_agent": "Mozilla/5.0 ...",
  "proxy": "",
  "insecure": false,
  "no_color": false,
  "follow_redirects": true,
  "max_requests": 5000,
  "allowed_hosts": ["*.example.com", "localhost"],
  "headers": {},
  "tampers": [],
  "techniques": ["error", "boolean", "time"]
}
```

### Scope allowlist

Set `allowed_hosts` to enforce a scope boundary. Exact hostnames, wildcard
subdomains and CIDR ranges are supported:

```json
{ "allowed_hosts": ["*.example.com", "10.0.0.0/8"] }
```

`sqli` refuses to run if a target host does not match the list. Leave the list
empty to disable the check.

## Tampers

Tampers transform payloads to get past filters and WAFs. Chain them in order:

```bash
sqli scan -u "..." --tamper space2comment,randomcase --authorized
```

| Name | Effect |
|---|---|
| `randomcase` | alternate upper and lower case |
| `space2comment` | replace spaces with `/**/` |
| `space2plus` | replace spaces with `+` |
| `space2randomblank` | random whitespace characters |
| `charencode` | percent-encode non-alphanumeric characters |
| `urlencode` | URL-encode the payload |
| `doubleurlencode` | double URL-encode |
| `apostrophe` | encode single quotes only |
| `equaltolike` | replace `=` with `LIKE` |
| `between` | replace `>` with `NOT BETWEEN 0 AND` |
| `comment` | alias of `space2comment` |
| `versionedmorekeywords` | wrap MySQL keywords in versioned comments |

## Safety

`sqli` sends active probes. Use it for authorized security testing, CTFs, lab
work and applications you own.

- Authorization is required. Interactive runs ask for confirmation;
  non-interactive runs require `--authorized` or `SQLI_AUTHORIZED=1`.
- Payloads are read-only. The library contains no `INSERT`, `UPDATE`, `DELETE`,
  `DROP`, file access or command execution. It performs comparisons, delays and
  version reads only.
- Scans are bounded by a hard request budget (default 5000) and an optional
  scope allowlist.
- Risk level 1 avoids OR-based expansion, and the crawler skips destructive
  links.

Unauthorized testing is illegal in most jurisdictions. You are responsible for
having written permission for every target you scan.

## Project layout

```
cmd/
  sqli/            CLI entry point
  vulnserver/      intentionally vulnerable demo app
internal/
  cli/             commands, flags, config merging, output wiring
  config/          JSON configuration
  crawl/           bounded breadth-first crawler
  detect/          engine, baselines, similarity, four techniques
  discover/        HTML tokenizer, forms, injection point extraction
  fingerprint/     DBMS signatures and version extraction
  httpx/           HTTP client, rate limiting, SOCKS5
  model/           request templates, injection points, findings
  payload/         payload library and tamper scripts
  rawreq/          raw HTTP and curl parsers
  report/          terminal, JSON and Markdown renderers
  ui/              colors, tables, progress, prompts
  version/         build metadata
```

Dependencies point one way: `model` and `httpx` are leaves, `detect` depends on
both, and `cli` depends on the rest. There are no import cycles.

## Development

```bash
make test          # go test ./...
make test-short    # skip timing tests
make vet           # go vet ./...
make build         # bin/sqli
make cross         # linux, macOS and Windows binaries
```

On Windows the same targets are available through PowerShell:

```powershell
.\build.ps1 check          # gofmt check, vet and tests
.\build.ps1 build
.\build.ps1 cross -Version 1.0.0
```

Releases use GoReleaser (`.goreleaser.yaml`). CI runs tests on Linux, macOS and
Windows (`.github/workflows/ci.yml`).

Run the race detector if cgo is available:

```bash
go test -race ./...
```

### Tests

- Unit tests for payloads, tampers, parsers, similarity and JSON injection.
- HTTP integration tests against an in-process vulnerable application.
- End-to-end tests for each technique, plus clean-target and request-budget
  tests.

## Limitations

- Detection only. `sqli` does not dump tables, read files or execute commands.
- Multipart form bodies are not parsed.
- Time-based tests need a reasonably stable network path. Use a larger
  `--time-delay` on high-latency links.
- Some WAFs block automated traffic regardless of tampers. Slow down with
  `--delay` and `--rate`.
- Confidence scores are heuristics, not proof. Validate findings manually
  before reporting them.

## License

MIT. Copyright 2026 Akshay Rajhans. See [LICENSE](LICENSE).
