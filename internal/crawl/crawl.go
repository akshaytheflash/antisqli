// Package crawl performs a bounded, polite breadth-first crawl of a target
// and produces scannable requests from links and forms.
package crawl

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/akshaytheflash/antisqli/internal/discover"
	"github.com/akshaytheflash/antisqli/internal/httpx"
)

// Options controls crawl behavior.
type Options struct {
	MaxDepth      int
	MaxPages      int
	SameHost      bool
	PathPrefix    string
	Exclude       []string
	Concurrency   int
	RespectRobots bool
	UserAgent     string
	Logger        func(format string, args ...any)
}

// Result holds discovered requests and statistics.
type Result struct {
	Requests []*http.Request
	Pages    int
	Errors   []string
	Visited  []string
}

var staticExtensions = map[string]bool{
	".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true,
	".avif": true, ".svg": true, ".ico": true, ".css": true, ".js": true,
	".map": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true,
	".mp4": true, ".webm": true, ".mp3": true, ".wav": true, ".pdf": true,
	".zip": true, ".gz": true, ".tar": true, ".rar": true, ".7z": true,
	".exe": true, ".dmg": true, ".iso": true, ".apk": true, ".bin": true,
}

// DefaultExclude prevents the crawler from following destructive GET links.
var DefaultExclude = []string{
	"logout", "signout", "sign-out", "delete", "remove", "destroy",
	"unsubscribe", "deactivate", "revoke", "reset-password", "cancel",
}

type item struct {
	url   string
	depth int
}

// Run crawls seeds and returns deduplicated scannable requests.
func Run(ctx context.Context, client *httpx.Client, seeds []string, opts Options) (*Result, error) {
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 2
	}
	if opts.MaxPages <= 0 {
		opts.MaxPages = 50
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 5
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "sqli/1.0"
	}
	exclude := opts.Exclude
	if exclude == nil {
		exclude = DefaultExclude
	}

	res := &Result{}
	seen := map[string]bool{}
	reqSeen := map[string]bool{}
	var mu sync.Mutex

	var queue []item
	for _, seed := range seeds {
		u, err := url.Parse(seed)
		if err != nil {
			return nil, fmt.Errorf("invalid seed %q: %w", seed, err)
		}
		queue = append(queue, item{url: u.String(), depth: 0})
	}

	allowed := map[string]bool{}
	var disallow []string
	if opts.RespectRobots {
		for _, seed := range seeds {
			u, _ := url.Parse(seed)
			if u == nil {
				continue
			}
			disallow = append(disallow, fetchRobots(ctx, client, u, opts.UserAgent)...)
		}
	}

	var pagesFetched atomic.Int64
	seedHost := hostOf(seeds[0])
	if seedHost != "" {
		allowed[seedHost] = true
	}

	for depth := 0; depth <= opts.MaxDepth && len(queue) > 0; depth++ {
		if ctx.Err() != nil {
			break
		}
		var next []item
		var wg sync.WaitGroup
		sem := make(chan struct{}, opts.Concurrency)

		for _, it := range queue {
			if pagesFetched.Load() >= int64(opts.MaxPages) {
				break
			}
			if seen[it.url] || !allowedURL(it.url, seedHost, opts, disallow) {
				continue
			}
			seen[it.url] = true
			wg.Add(1)
			sem <- struct{}{}
			go func(it item) {
				defer wg.Done()
				defer func() { <-sem }()
				if pagesFetched.Add(1) > int64(opts.MaxPages) {
					return
				}

				req, err := http.NewRequestWithContext(ctx, http.MethodGet, it.url, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", opts.UserAgent)
				resp, err := client.Do(ctx, req)
				if err != nil || resp == nil || resp.Err != nil {
					mu.Lock()
					if err != nil {
						res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", it.url, err))
					}
					mu.Unlock()
					return
				}

				mu.Lock()
				res.Pages++
				res.Visited = append(res.Visited, it.url)
				if isScannableURL(it.url) && !reqSeen["GET "+it.url] {
					reqSeen["GET "+it.url] = true
					if r, err := http.NewRequest(http.MethodGet, it.url, nil); err == nil {
						res.Requests = append(res.Requests, r)
					}
				}
				mu.Unlock()

				ct := strings.ToLower(resp.Header.Get("Content-Type"))
				if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
					return
				}
				page := discover.ParseHTML(resp.Body, req.URL)
				for _, link := range page.Links {
					mu.Lock()
					next = append(next, item{url: normalize(link), depth: it.depth + 1})
					mu.Unlock()
				}
				for _, form := range page.Forms {
					fr, err := discover.FormsToRequests(form)
					if err != nil || fr == nil {
						continue
					}
					key := fr.Method + " " + fr.URL.String() + "|" + bodyString(fr)
					mu.Lock()
					if !reqSeen[key] {
						reqSeen[key] = true
						res.Requests = append(res.Requests, fr)
					}
					mu.Unlock()
				}
			}(it)
		}
		wg.Wait()
		queue = next
	}

	// Stable ordering keeps reports reproducible.
	sort.SliceStable(res.Requests, func(i, j int) bool {
		return res.Requests[i].URL.String() < res.Requests[j].URL.String()
	})
	return res, nil
}

func bodyString(r *http.Request) string {
	if r == nil || r.GetBody == nil {
		return ""
	}
	rc, err := r.GetBody()
	if err != nil {
		return ""
	}
	defer rc.Close()
	buf := make([]byte, 4096)
	n, _ := rc.Read(buf)
	return string(buf[:n])
}

func isScannableURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.RawQuery != ""
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func allowedURL(raw, seedHost string, opts Options, disallow []string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	if opts.SameHost && seedHost != "" && strings.ToLower(u.Hostname()) != seedHost {
		return false
	}
	if opts.PathPrefix != "" && !strings.HasPrefix(u.Path, opts.PathPrefix) {
		return false
	}
	lower := strings.ToLower(u.Path)
	for ext := range staticExtensions {
		if strings.HasSuffix(lower, ext) {
			return false
		}
	}
	for _, ex := range opts.Exclude {
		if ex != "" && strings.Contains(strings.ToLower(raw), strings.ToLower(ex)) {
			return false
		}
	}
	for _, d := range disallow {
		if d != "" && strings.HasPrefix(u.Path, d) {
			return false
		}
	}
	return true
}

func normalize(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	q := u.Query()
	u.RawQuery = q.Encode()
	return u.String()
}

// fetchRobots returns Disallow paths from robots.txt.
func fetchRobots(ctx context.Context, client *httpx.Client, u *url.URL, ua string) []string {
	robots := &url.URL{Scheme: u.Scheme, Host: u.Host, Path: "/robots.txt"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, robots.String(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(ctx, req)
	if err != nil || resp == nil || resp.Status != 200 {
		return nil
	}
	var out []string
	applies := false
	for _, line := range strings.Split(resp.Text(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		switch key {
		case "user-agent":
			applies = value == "*"
		case "disallow":
			if applies && value != "" {
				out = append(out, value)
			}
		}
	}
	return out
}
