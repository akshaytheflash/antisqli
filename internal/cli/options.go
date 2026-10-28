package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/akshaytheflash/antisqli/internal/config"
	"github.com/akshaytheflash/antisqli/internal/payload"
)

// stringList is a repeatable flag value.
type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ", ") }

func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// Options holds all scan parameters after flag and config merging.
type Options struct {
	URL          string
	RequestFile  string
	Curl         string
	ListFile     string
	Scheme       string
	Method       string
	Data         string
	Cookie       string
	Headers      stringList
	HeaderPoints stringList
	Params       stringList
	SkipParams   stringList

	TechniqueFlag string
	Techniques    []payload.Technique
	DBMS          string
	Level         int
	Risk          int
	Tampers       stringList
	TamperList    []string

	TimeDelay   int
	Samples     int
	Concurrency int
	Timeout     int
	DelayMS     int
	Rate        float64
	Retries     int
	MaxRequests int64
	Thorough    bool

	Proxy           string
	Insecure        bool
	FollowRedirects bool
	NoRedirect      bool
	UserAgent       string

	Crawl         bool
	Depth         int
	MaxPages      int
	SameHost      bool
	RespectRobots bool
	Exclude       stringList
	PathSegments  bool

	Output     string
	Format     string
	JSONOutput bool
	ListPoints bool

	Authorized bool
	Quiet      bool
	Verbose    bool
	NoColor    bool
	ConfigPath string
}

// defaultOptions builds options from persisted configuration.
func defaultOptions(cfg config.Config) *Options {
	return &Options{
		Level:           cfg.Level,
		Risk:            cfg.Risk,
		DBMS:            "",
		TechniqueFlag:   strings.Join(cfg.Techniques, ","),
		TimeDelay:       cfg.TimeDelay,
		Samples:         cfg.Samples,
		Concurrency:     cfg.Concurrency,
		Timeout:         cfg.Timeout,
		DelayMS:         cfg.DelayMS,
		Rate:            cfg.Rate,
		Retries:         cfg.Retries,
		MaxRequests:     cfg.MaxRequests,
		Proxy:           cfg.Proxy,
		Insecure:        cfg.Insecure,
		FollowRedirects: cfg.FollowRedirects,
		UserAgent:       cfg.UserAgent,
		Scheme:          "https",
		Depth:           2,
		MaxPages:        50,
		SameHost:        true,
		Format:          cfg.Format,
		Output:          cfg.Output,
		NoColor:         cfg.NoColor,
	}
}

// bindFlags registers scan flags on fs.
func bindFlags(fs *flag.FlagSet, o *Options) {
	fs.StringVar(&o.URL, "u", o.URL, "target URL")
	fs.StringVar(&o.URL, "url", o.URL, "target URL")
	fs.StringVar(&o.RequestFile, "r", o.RequestFile, "raw HTTP request file (Burp/devtools export)")
	fs.StringVar(&o.RequestFile, "request", o.RequestFile, "raw HTTP request file")
	fs.StringVar(&o.Curl, "curl", o.Curl, "curl command to replay")
	fs.StringVar(&o.ListFile, "l", o.ListFile, "file with one URL per line (use - for stdin)")
	fs.StringVar(&o.ListFile, "list", o.ListFile, "file with one URL per line")
	fs.StringVar(&o.Scheme, "scheme", o.Scheme, "scheme for raw requests: http or https")

	fs.StringVar(&o.Method, "X", o.Method, "HTTP method override")
	fs.StringVar(&o.Method, "method", o.Method, "HTTP method override")
	fs.StringVar(&o.Data, "d", o.Data, "request body (form or JSON)")
	fs.StringVar(&o.Data, "data", o.Data, "request body")
	fs.StringVar(&o.Cookie, "b", o.Cookie, "Cookie header value")
	fs.StringVar(&o.Cookie, "cookie", o.Cookie, "Cookie header value")
	fs.Var(&o.Headers, "H", "extra header \"Name: value\" (repeatable)")
	fs.Var(&o.Headers, "header", "extra header \"Name: value\" (repeatable)")

	fs.Var(&o.Params, "p", "test only these parameters (comma separated, repeatable)")
	fs.Var(&o.Params, "param", "test only these parameters")
	fs.Var(&o.SkipParams, "skip", "parameters to ignore")
	fs.Var(&o.HeaderPoints, "header-point", "header to treat as injectable (repeatable)")

	fs.StringVar(&o.TechniqueFlag, "technique", o.TechniqueFlag, "techniques: error,boolean,time,union,all")
	fs.StringVar(&o.DBMS, "dbms", o.DBMS, "assume backend: mysql,postgres,mssql,oracle,sqlite")
	fs.IntVar(&o.Level, "level", o.Level, "payload coverage 1-3")
	fs.IntVar(&o.Risk, "risk", o.Risk, "payload risk 1-3")
	fs.Var(&o.Tampers, "tamper", "tamper script (repeatable)")

	fs.IntVar(&o.TimeDelay, "time-delay", o.TimeDelay, "seconds to delay in time-based tests")
	fs.IntVar(&o.Samples, "samples", o.Samples, "baseline/timing samples")
	fs.IntVar(&o.Concurrency, "concurrency", o.Concurrency, "parallel workers")
	fs.IntVar(&o.Timeout, "timeout", o.Timeout, "per-request timeout in seconds")
	fs.IntVar(&o.DelayMS, "delay", o.DelayMS, "delay between requests in milliseconds")
	fs.Float64Var(&o.Rate, "rate", o.Rate, "max requests per second (0 = unlimited)")
	fs.IntVar(&o.Retries, "retries", o.Retries, "retries for transient failures")
	fs.Int64Var(&o.MaxRequests, "max-requests", o.MaxRequests, "hard request budget")
	fs.BoolVar(&o.Thorough, "thorough", o.Thorough, "run every technique on every parameter")

	fs.StringVar(&o.Proxy, "proxy", o.Proxy, "proxy URL (http, https, socks5)")
	fs.BoolVar(&o.Insecure, "k", o.Insecure, "skip TLS verification")
	fs.BoolVar(&o.Insecure, "insecure", o.Insecure, "skip TLS verification")
	fs.BoolVar(&o.FollowRedirects, "follow-redirects", o.FollowRedirects, "follow redirects")
	fs.BoolVar(&o.NoRedirect, "no-redirect", false, "do not follow redirects")
	fs.StringVar(&o.UserAgent, "A", o.UserAgent, "User-Agent header")
	fs.StringVar(&o.UserAgent, "user-agent", o.UserAgent, "User-Agent header")

	fs.BoolVar(&o.Crawl, "crawl", o.Crawl, "crawl the target for parameters and forms")
	fs.IntVar(&o.Depth, "depth", o.Depth, "crawl depth")
	fs.IntVar(&o.MaxPages, "max-pages", o.MaxPages, "maximum pages to crawl")
	fs.BoolVar(&o.SameHost, "same-host", o.SameHost, "stay on the seed host")
	fs.BoolVar(&o.RespectRobots, "respect-robots", o.RespectRobots, "honor robots.txt")
	fs.Var(&o.Exclude, "exclude", "skip URLs containing this substring (repeatable)")
	fs.BoolVar(&o.PathSegments, "path-segments", o.PathSegments, "test path segments at level 2+")

	fs.StringVar(&o.Output, "o", o.Output, "write report to file (.json or .md)")
	fs.StringVar(&o.Output, "output", o.Output, "write report to file")
	fs.StringVar(&o.Format, "format", o.Format, "output format: text, json, markdown")
	fs.BoolVar(&o.JSONOutput, "json", o.JSONOutput, "print JSON to stdout")
	fs.BoolVar(&o.ListPoints, "list-points", o.ListPoints, "list injectable parameters and exit")

	fs.BoolVar(&o.Authorized, "authorized", o.Authorized, "confirm you have permission to test the target")
	fs.BoolVar(&o.Quiet, "q", o.Quiet, "suppress banner and progress")
	fs.BoolVar(&o.Quiet, "quiet", o.Quiet, "suppress banner and progress")
	fs.BoolVar(&o.Verbose, "v", o.Verbose, "verbose debug output")
	fs.BoolVar(&o.Verbose, "verbose", o.Verbose, "verbose debug output")
	fs.BoolVar(&o.NoColor, "no-color", o.NoColor, "disable ANSI colors")
	fs.StringVar(&o.ConfigPath, "config", o.ConfigPath, "config file path")
}

// finalize validates and normalizes options.
func (o *Options) finalize() error {
	techs, err := parseTechniques(o.TechniqueFlag)
	if err != nil {
		return err
	}
	o.Techniques = techs

	if o.JSONOutput {
		o.Format = "json"
	}
	if o.Format != "" {
		f := strings.ToLower(o.Format)
		switch f {
		case "text", "txt":
			o.Format = "text"
		case "json":
			o.Format = "json"
		case "markdown", "md":
			o.Format = "markdown"
		default:
			return fmt.Errorf("unknown format %q (use text, json or markdown)", o.Format)
		}
	}
	o.TamperList = splitCSV(o.Tampers)
	for _, t := range o.TamperList {
		if !payload.ValidateTamper(t) {
			return fmt.Errorf("unknown tamper %q; run 'sqli tampers' for the list", t)
		}
	}
	if o.NoRedirect {
		o.FollowRedirects = false
	}

	if o.Level < 1 || o.Level > 3 {
		return fmt.Errorf("--level must be between 1 and 3")
	}
	if o.Risk < 1 || o.Risk > 3 {
		return fmt.Errorf("--risk must be between 1 and 3")
	}
	if o.Concurrency < 1 || o.Concurrency > 128 {
		return fmt.Errorf("--concurrency must be between 1 and 128")
	}
	if o.Timeout < 1 || o.Timeout > 300 {
		return fmt.Errorf("--timeout must be between 1 and 300 seconds")
	}
	if o.TimeDelay < 1 || o.TimeDelay > 30 {
		return fmt.Errorf("--time-delay must be between 1 and 30 seconds")
	}
	if o.Samples < 2 || o.Samples > 10 {
		return fmt.Errorf("--samples must be between 2 and 10")
	}
	if o.DelayMS < 0 {
		return fmt.Errorf("--delay cannot be negative")
	}
	if o.Rate < 0 {
		return fmt.Errorf("--rate cannot be negative")
	}
	if o.MaxRequests < 0 {
		return fmt.Errorf("--max-requests cannot be negative")
	}
	if o.DBMS != "" {
		o.DBMS = normalizeDBMSName(o.DBMS)
	}
	switch strings.ToLower(o.Scheme) {
	case "", "https":
		o.Scheme = "https"
	case "http":
		o.Scheme = "http"
	default:
		return fmt.Errorf("--scheme must be http or https")
	}
	return nil
}

func parseTechniques(raw string) ([]payload.Technique, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" || raw == "all" {
		return append([]payload.Technique(nil), payload.AllTechniques...), nil
	}
	seen := map[payload.Technique]bool{}
	var out []payload.Technique
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		t, err := payload.ParseTechnique(part)
		if err != nil {
			return nil, err
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no techniques selected")
	}
	return out, nil
}

func splitCSV(items []string) []string {
	var out []string
	for _, item := range items {
		for _, part := range strings.Split(item, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func normalizeDBMSName(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "mysql", "mariadb":
		return "mysql"
	case "postgres", "postgresql", "pgsql":
		return "postgres"
	case "mssql", "sqlserver", "sql server":
		return "mssql"
	case "oracle":
		return "oracle"
	case "sqlite", "sqlite3":
		return "sqlite"
	}
	return strings.ToLower(strings.TrimSpace(s))
}

// findConfigArg extracts --config from args before flag parsing so defaults
// can be loaded from the requested file.
func findConfigArg(args []string) string {
	for i, a := range args {
		if a == "--config" || a == "-config" {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
		if strings.HasPrefix(a, "--config=") {
			return strings.TrimPrefix(a, "--config=")
		}
		if strings.HasPrefix(a, "-config=") {
			return strings.TrimPrefix(a, "-config=")
		}
	}
	if env := os.Getenv("SQLI_CONFIG"); env != "" {
		return env
	}
	return ""
}
