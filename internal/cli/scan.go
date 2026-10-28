package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/akshaytheflash/antisqli/internal/config"
	"github.com/akshaytheflash/antisqli/internal/crawl"
	"github.com/akshaytheflash/antisqli/internal/detect"
	"github.com/akshaytheflash/antisqli/internal/discover"
	"github.com/akshaytheflash/antisqli/internal/httpx"
	"github.com/akshaytheflash/antisqli/internal/model"
	"github.com/akshaytheflash/antisqli/internal/payload"
	"github.com/akshaytheflash/antisqli/internal/rawreq"
	"github.com/akshaytheflash/antisqli/internal/report"
	"github.com/akshaytheflash/antisqli/internal/ui"
	"github.com/akshaytheflash/antisqli/internal/version"
)

func runScan(u *ui.UI, args []string, forceCrawl bool) int {
	cfg, cfgPath, err := config.Load(findConfigArg(args))
	if err != nil {
		u.Error("%v", err)
		return 2
	}
	o := defaultOptions(cfg)
	o.ConfigPath = cfgPath

	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	bindFlags(fs, o)
	fs.Usage = func() {}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printScanHelp(u)
			return 0
		}
		u.Error("%v", err)
		u.Printf("Run %s for usage.", u.Cyan("sqli help scan"))
		return 2
	}
	if forceCrawl {
		o.Crawl = true
	}
	if err := o.finalize(); err != nil {
		u.Error("%v", err)
		return 2
	}
	// Machine readable stdout must not be polluted by banners or panels.
	if o.Output == "" && (o.Format == "json" || o.Format == "markdown") {
		o.Quiet = true
	}
	u.Configure(!o.NoColor && os.Getenv("NO_COLOR") == "" && ui.IsTTY(os.Stdout), o.Quiet, o.Verbose)
	if o.Format != "json" && !o.JSONOutput {
		u.Banner(version.Name, version.Tagline, version.String())
	}

	if o.URL == "" && o.RequestFile == "" && o.Curl == "" && o.ListFile == "" {
		if ui.IsTTY(os.Stdin) {
			o.URL = u.Prompt("Target URL", "")
			if o.URL != "" && !strings.Contains(o.URL, "://") {
				o.URL = "https://" + o.URL
			}
		}
		if o.URL == "" {
			printScanHelp(u)
			return 2
		}
	}

	reqs, err := buildRequests(o)
	if err != nil {
		u.Error("%v", err)
		return 2
	}
	if len(reqs) == 0 {
		u.Error("no requests to scan")
		return 2
	}
	if err := scopeAllowed(cfg, reqs); err != nil {
		u.Error("%v", err)
		return 2
	}
	// Listing parameters is offline unless a crawl is requested.
	if o.ListPoints && !o.Crawl {
		return listPoints(u, collectPoints(reqs, o))
	}
	if !authorize(u, o, reqs) {
		return 2
	}

	client, err := newClient(o)
	if err != nil {
		u.Error("%v", err)
		return 2
	}
	defer client.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	started := time.Now()
	requests := reqs
	var crawlInfo string
	if o.Crawl {
		seeds := make([]string, 0, len(reqs))
		for _, r := range reqs {
			seeds = append(seeds, r.URL.String())
		}
		u.Info("Crawling %d seed(s) to depth %d (max %d pages)...", len(seeds), o.Depth, o.MaxPages)
		cr, err := crawl.Run(ctx, client, seeds, crawl.Options{
			MaxDepth:      o.Depth,
			MaxPages:      o.MaxPages,
			SameHost:      o.SameHost,
			Exclude:       splitCSV(o.Exclude),
			Concurrency:   minInt(o.Concurrency, 8),
			RespectRobots: o.RespectRobots,
			UserAgent:     o.UserAgent,
			Logger:        u.Debug,
		})
		if err != nil {
			u.Error("crawl failed: %v", err)
			return 2
		}
		if len(cr.Requests) > 0 {
			requests = cr.Requests
		}
		crawlInfo = fmt.Sprintf("%d pages, %d requests", cr.Pages, len(requests))
		for _, e := range cr.Errors {
			u.Debug("%s", e)
		}
	}

	points := collectPoints(requests, o)
	if o.ListPoints {
		return listPoints(u, points)
	}
	if len(points) == 0 {
		u.Warn("no injectable parameters found")
		u.Printf("  %s", u.Dim("Supply a URL with a query string, a form body via -d, or use --crawl."))
		return 2
	}

	printTargetPanel(u, o, points, crawlInfo)

	progStatic := u.NewProgress("scanning parameters", len(points))
	progTime := u.NewProgress("timing payloads", len(points))

	eng, err := detect.New(client, detect.Options{
		Techniques:  o.Techniques,
		Level:       o.Level,
		Risk:        o.Risk,
		DBMS:        o.DBMS,
		Concurrency: o.Concurrency,
		Samples:     o.Samples,
		TimeDelay:   o.TimeDelay,
		MaxRequests: o.MaxRequests,
		Thorough:    o.Thorough,
		Tampers:     o.TamperList,
		Debugf:      u.Debug,
		Progress: func(phase string, done, total int, p model.Point) {
			if phase == "time" {
				progTime.Set(done)
			} else {
				progStatic.Set(done)
			}
		},
	})
	if err != nil {
		u.Error("%v", err)
		return 2
	}

	u.Section("Scan")
	u.Info("Testing %d parameter(s) with %s...", len(points), techniqueList(o.Techniques))

	res := eng.Scan(ctx, points)

	progStatic.Done()
	progTime.Done()

	rep := report.New(targetLabel(reqs), started)
	rep.DurationMS = res.Duration.Milliseconds()
	rep.Requests = res.Requests
	rep.Points = res.Points
	rep.DBMS = res.DBMS
	rep.WAF = res.WAF
	rep.Findings = res.Findings
	rep.Errors = res.Errors
	rep.Blocked = res.Blocked
	for _, t := range o.Techniques {
		rep.Techniques = append(rep.Techniques, string(t))
	}

	if ctx.Err() != nil {
		u.Warn("scan interrupted; showing partial results")
	}

	if err := emitReport(u, rep, o); err != nil {
		u.Error("write report: %v", err)
		return 2
	}

	if len(res.Findings) > 0 {
		return 1
	}
	return 0
}

func newClient(o *Options) (*httpx.Client, error) {
	headers := map[string]string{}
	for _, h := range o.Headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("invalid header %q (expected \"Name: value\")", h)
		}
		headers[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	if o.Cookie != "" {
		headers["Cookie"] = o.Cookie
	}
	jitter := time.Duration(0)
	if o.DelayMS > 0 {
		jitter = time.Duration(o.DelayMS/2) * time.Millisecond
	}
	burst := int(o.Rate)
	if burst < 1 {
		burst = 1
	}
	return httpx.New(httpx.Options{
		Timeout:        time.Duration(o.Timeout) * time.Second,
		Insecure:       o.Insecure,
		Proxy:          o.Proxy,
		Rate:           o.Rate,
		Burst:          burst,
		Retries:        o.Retries,
		RetryBackoff:   300 * time.Millisecond,
		Delay:          time.Duration(o.DelayMS) * time.Millisecond,
		Jitter:         jitter,
		UserAgent:      o.UserAgent,
		FollowRedirect: o.FollowRedirects,
		Headers:        headers,
	})
}

func buildRequests(o *Options) ([]*http.Request, error) {
	sources := 0
	for _, v := range []string{o.URL, o.RequestFile, o.Curl, o.ListFile} {
		if v != "" {
			sources++
		}
	}
	if sources == 0 {
		return nil, fmt.Errorf("no target specified")
	}
	if sources > 1 {
		return nil, fmt.Errorf("use only one of --url, --request, --curl or --list")
	}

	switch {
	case o.Curl != "":
		req, insecure, err := rawreq.ParseCurl(o.Curl)
		if err != nil {
			return nil, err
		}
		if insecure {
			o.Insecure = true
		}
		if err := applyOverrides(req, o); err != nil {
			return nil, err
		}
		return []*http.Request{req}, nil

	case o.RequestFile != "":
		data, err := os.ReadFile(o.RequestFile)
		if err != nil {
			return nil, fmt.Errorf("read request file: %w", err)
		}
		req, err := rawreq.ParseRaw(data, o.Scheme)
		if err != nil {
			return nil, err
		}
		if err := applyOverrides(req, o); err != nil {
			return nil, err
		}
		return []*http.Request{req}, nil

	case o.ListFile != "":
		var data []byte
		var err error
		if o.ListFile == "-" {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(o.ListFile)
		}
		if err != nil {
			return nil, fmt.Errorf("read list: %w", err)
		}
		var reqs []*http.Request
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			req, err := buildURLRequest(line, o)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", line, err)
			}
			reqs = append(reqs, req)
		}
		return reqs, nil

	default:
		req, err := buildURLRequest(o.URL, o)
		if err != nil {
			return nil, err
		}
		return []*http.Request{req}, nil
	}
}

func buildURLRequest(raw string, o *Options) (*http.Request, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	method := strings.ToUpper(o.Method)
	if method == "" {
		if o.Data != "" {
			method = http.MethodPost
		} else {
			method = http.MethodGet
		}
	}
	var body io.Reader
	if o.Data != "" {
		body = strings.NewReader(o.Data)
	}
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	if err := applyOverrides(req, o); err != nil {
		return nil, err
	}
	return req, nil
}

func applyOverrides(req *http.Request, o *Options) error {
	if o.Method != "" {
		req.Method = strings.ToUpper(o.Method)
	}
	for _, h := range o.Headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok || strings.TrimSpace(name) == "" {
			return fmt.Errorf("invalid header %q (expected \"Name: value\")", h)
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	if o.Cookie != "" {
		req.Header.Set("Cookie", o.Cookie)
	}
	if o.Data != "" {
		body := strings.NewReader(o.Data)
		req.Body = io.NopCloser(body)
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(o.Data)), nil
		}
		req.ContentLength = int64(len(o.Data))
		if req.Header.Get("Content-Type") == "" {
			if looksLikeJSON(o.Data) {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
		}
	}
	if o.UserAgent != "" && req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", o.UserAgent)
	}
	return nil
}

func looksLikeJSON(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")
}

func authorize(u *ui.UI, o *Options, reqs []*http.Request) bool {
	if o.Authorized || os.Getenv("SQLI_AUTHORIZED") == "1" {
		return true
	}
	hosts := uniqueHosts(reqs)
	if !ui.IsTTY(os.Stdin) || !ui.IsTTY(os.Stderr) {
		u.Error("authorization required: re-run with --authorized (or set SQLI_AUTHORIZED=1)")
		u.Printf("  %s", u.Dim("Only test systems you own or have written permission to assess."))
		return false
	}
	u.Warn("sqli sends active SQL injection probes. Unauthorized testing is illegal.")
	u.Printf("  %s %s", u.Dim("Targets:"), strings.Join(hosts, ", "))
	return u.Confirm("Do you have authorization to test these targets?")
}

func scopeAllowed(cfg config.Config, reqs []*http.Request) error {
	if len(cfg.AllowedHosts) == 0 {
		return nil
	}
	for _, r := range reqs {
		host := strings.ToLower(r.URL.Hostname())
		if !hostMatches(host, cfg.AllowedHosts) {
			return fmt.Errorf("target %q is outside the configured allowed_hosts (%s)", host, strings.Join(cfg.AllowedHosts, ", "))
		}
	}
	return nil
}

func hostMatches(host string, allowed []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if strings.Contains(a, "/") {
			if _, network, err := net.ParseCIDR(a); err == nil {
				if ip := net.ParseIP(host); ip != nil && network.Contains(ip) {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(a, "*.") {
			if strings.HasSuffix(host, a[1:]) || host == a[2:] {
				return true
			}
			continue
		}
		if host == a {
			return true
		}
	}
	return false
}

func uniqueHosts(reqs []*http.Request) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range reqs {
		if r.URL == nil {
			continue
		}
		h := r.URL.Host
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}

func targetLabel(reqs []*http.Request) string {
	if len(reqs) == 1 {
		return reqs[0].URL.String()
	}
	return fmt.Sprintf("%d endpoints", len(reqs))
}

func printTargetPanel(u *ui.UI, o *Options, points []model.Point, crawlInfo string) {
	u.Section("Target")
	if o.URL != "" {
		u.KV("URL", o.URL)
	}
	if o.RequestFile != "" {
		u.KV("Request", o.RequestFile)
	}
	if o.Curl != "" {
		u.KV("Source", "curl command")
	}
	if crawlInfo != "" {
		u.KV("Crawled", crawlInfo)
	}
	u.KV("Parameters", fmt.Sprintf("%d (%s)", len(points), previewNames(points, 8)))
	u.KV("Techniques", techniqueList(o.Techniques))
	u.KV("Level/Risk", fmt.Sprintf("%d/%d", o.Level, o.Risk))
	if o.DBMS != "" {
		u.KV("Backend", o.DBMS)
	}
	if o.Proxy != "" {
		u.KV("Proxy", o.Proxy)
	}
	if len(o.TamperList) > 0 {
		u.KV("Tampers", strings.Join(o.TamperList, ", "))
	}
	if o.MaxRequests > 0 {
		u.KV("Budget", fmt.Sprintf("%d requests", o.MaxRequests))
	}
}

func previewNames(points []model.Point, max int) string {
	seen := map[string]bool{}
	var names []string
	for _, p := range points {
		if seen[p.Name] {
			continue
		}
		seen[p.Name] = true
		names = append(names, p.Name)
		if len(names) == max {
			return strings.Join(names, ", ") + ", ..."
		}
	}
	return strings.Join(names, ", ")
}

func techniqueList(ts []payload.Technique) string {
	names := make([]string, len(ts))
	for i, t := range ts {
		names[i] = string(t)
	}
	return strings.Join(names, ", ")
}

func collectPoints(reqs []*http.Request, o *Options) []model.Point {
	dopts := discover.Options{
		Level:    o.Level,
		Params:   splitCSV(o.Params),
		Skip:     splitCSV(o.SkipParams),
		Headers:  splitCSV(o.HeaderPoints),
		PathSegs: o.PathSegments,
	}
	var points []model.Point
	for _, req := range reqs {
		points = append(points, discover.PointsFromRequest(req, dopts)...)
	}
	return points
}

func listPoints(u *ui.UI, points []model.Point) int {
	if len(points) == 0 {
		u.Warn("no injectable parameters found")
		u.Printf("  %s", u.Dim("Supply a URL with a query string, a form body via -d, or use --crawl."))
		return 2
	}
	u.Section(fmt.Sprintf("Injectable parameters (%d)", len(points)))
	rows := make([][]string, 0, len(points))
	for i, p := range points {
		original := p.Original
		if len(original) > 40 {
			original = original[:40] + "..."
		}
		rows = append(rows, []string{
			fmt.Sprintf("%d", i+1),
			p.Location.String(),
			p.Name,
			original,
			p.Method + " " + p.URL.Scheme + "://" + p.URL.Host + p.URL.Path,
		})
	}
	u.Table([]string{"#", "Location", "Parameter", "Original", "Endpoint"}, rows)
	return 0
}

func emitReport(u *ui.UI, rep *report.Report, o *Options) error {
	format := o.Format
	if format == "" {
		if inferred := report.FormatFromPath(o.Output); inferred != "" {
			format = inferred
		} else {
			format = "text"
		}
	}
	if o.Output != "" {
		f, err := os.Create(o.Output)
		if err != nil {
			return err
		}
		defer f.Close()
		switch format {
		case "json":
			if err := report.WriteJSON(f, rep); err != nil {
				return err
			}
		case "markdown":
			if err := report.WriteMarkdown(f, rep); err != nil {
				return err
			}
		default:
			fileUI := ui.New(ui.Options{Out: f, Err: io.Discard, Color: false})
			report.Terminal(fileUI, rep)
		}
		u.Success("Report written to %s", o.Output)
		if format == "text" {
			report.Terminal(u.WithQuiet(false), rep)
		}
		return nil
	}

	switch format {
	case "json":
		return report.WriteJSON(os.Stdout, rep)
	case "markdown":
		return report.WriteMarkdown(os.Stdout, rep)
	default:
		report.Terminal(u.WithQuiet(false), rep)
		return nil
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
