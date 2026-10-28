// Package httpx provides a resilient HTTP client tailored for security
// testing: rate limiting, retries, redirect control, proxy support and
// request/response instrumentation.
package httpx

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akshaytheflash/antisqli/internal/model"
)

// Options configures a Client.
type Options struct {
	Timeout        time.Duration
	Insecure       bool
	Proxy          string
	Rate           float64 // requests per second, 0 = unlimited
	Burst          int
	Retries        int
	RetryBackoff   time.Duration
	Delay          time.Duration
	Jitter         time.Duration
	UserAgent      string
	MaxBody        int64
	FollowRedirect bool
	MaxRedirects   int
	Headers        map[string]string
	Logger         func(format string, args ...any)
}

// Client is a concurrency-safe HTTP client.
type Client struct {
	hc      *http.Client
	opts    Options
	limiter *tokenBucket
	rand    *rand.Rand
	randMu  sync.Mutex
	reqs    atomic.Int64
	blocked atomic.Int64
}

// New creates a Client.
func New(opts Options) (*Client, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Retries < 0 {
		opts.Retries = 0
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 4 << 20
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 10
	}
	if opts.Burst <= 0 {
		opts.Burst = 1
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "sqli/1.0"
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: opts.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   opts.Timeout,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opts.Insecure, //nolint:gosec // explicit user opt-in
			MinVersion:         tls.VersionTLS12,
		},
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy %q: %w", opts.Proxy, err)
		}
		switch strings.ToLower(proxyURL.Scheme) {
		case "socks5", "socks5h":
			dial, err := socks5Dialer(proxyURL, opts.Timeout)
			if err != nil {
				return nil, err
			}
			transport.Proxy = nil
			transport.DialContext = dial
		case "http", "https":
			transport.Proxy = http.ProxyURL(proxyURL)
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q (use http, https, socks5)", proxyURL.Scheme)
		}
	}

	c := &Client{
		opts: opts,
		rand: rand.New(rand.NewSource(time.Now().UnixNano())), //nolint:gosec // jitter only
	}
	c.hc = &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !opts.FollowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= opts.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", opts.MaxRedirects)
			}
			return nil
		},
	}
	if opts.Rate > 0 {
		c.limiter = newTokenBucket(opts.Rate, opts.Burst)
	}
	return c, nil
}

// Requests returns the total number of HTTP requests issued.
func (c *Client) Requests() int64 { return c.reqs.Load() }

// Blocked returns the number of requests rejected by the request budget.
func (c *Client) Blocked() int64 { return c.blocked.Load() }

// Options returns a copy of the client options.
func (c *Client) Options() Options { return c.opts }

// Do sends req and returns a normalized response. Transport errors are
// returned both in the response and as the error value.
func (c *Client) Do(ctx context.Context, req *http.Request) (*model.Response, error) {
	if req.Header == nil {
		req.Header = http.Header{}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.opts.UserAgent)
	}
	for k, v := range c.opts.Headers {
		if req.Header.Get(k) == "" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Accept", headerOr(req, "Accept", "*/*"))
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}

	resp := &model.Response{Method: req.Method, URL: req.URL.String()}
	var lastErr error

	for attempt := 0; attempt <= c.opts.Retries; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, backoff(c.opts.RetryBackoff, attempt)); err != nil {
				resp.Err = err
				return resp, err
			}
		}
		if c.limiter != nil {
			if err := c.limiter.Wait(ctx); err != nil {
				resp.Err = err
				return resp, err
			}
		}
		if c.opts.Delay > 0 || c.opts.Jitter > 0 {
			d := c.opts.Delay
			if c.opts.Jitter > 0 {
				c.randMu.Lock()
				d += time.Duration(c.rand.Int63n(int64(c.opts.Jitter) + 1))
				c.randMu.Unlock()
			}
			if err := sleepCtx(ctx, d); err != nil {
				resp.Err = err
				return resp, err
			}
		}

		c.reqs.Add(1)
		start := time.Now()
		httpResp, err := c.hc.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			lastErr = err
			resp.Err = err
			resp.Duration = elapsed
			if ctx.Err() != nil {
				return resp, err
			}
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(httpResp.Body, c.opts.MaxBody))
		httpResp.Body.Close()
		resp.Status = httpResp.StatusCode
		resp.Header = httpResp.Header
		resp.Body = body
		resp.Duration = elapsed
		resp.Err = nil
		if readErr != nil {
			resp.Err = readErr
			lastErr = readErr
			continue
		}

		if isRetryableStatus(httpResp.StatusCode) && attempt < c.opts.Retries {
			lastErr = fmt.Errorf("server returned %s", httpResp.Status)
			if ra := retryAfter(httpResp.Header.Get("Retry-After")); ra > 0 {
				_ = sleepCtx(ctx, ra)
			}
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("request failed")
	}
	resp.Err = lastErr
	return resp, lastErr
}

// Get performs a GET request against rawurl.
func (c *Client) Get(ctx context.Context, rawurl string) (*model.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(ctx, req)
}

// Close releases idle connections.
func (c *Client) Close() {
	if tr, ok := c.hc.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// DumpRequest renders a request as it would appear on the wire. It never
// mutates req and never sends it.
func DumpRequest(req *http.Request) string {
	if req == nil {
		return ""
	}
	var b strings.Builder
	path := req.URL.RequestURI()
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, path)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	for k, vals := range req.Header {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vals {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	if len(req.Header.Values("Cookie")) > 0 {
		fmt.Fprintf(&b, "Cookie: %s\r\n", req.Header.Get("Cookie"))
	}
	if req.ContentLength > 0 {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", req.ContentLength)
	}
	b.WriteString("\r\n")
	if req.GetBody != nil {
		if rc, err := req.GetBody(); err == nil {
			data, _ := io.ReadAll(io.LimitReader(rc, 64<<10))
			rc.Close()
			b.Write(bytes.TrimRight(data, "\r\n"))
		}
	}
	return b.String()
}

func headerOr(req *http.Request, key, def string) string {
	if v := req.Header.Get(key); v != "" {
		return v
	}
	return def
}

func isRetryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code == http.StatusRequestTimeout || code >= 500
}

func retryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := time.ParseDuration(v + "s"); err == nil && secs > 0 && secs <= 30*time.Second {
		return secs
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d > 0 && d <= 30*time.Second {
			return d
		}
	}
	return 0
}

func backoff(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 250 * time.Millisecond
	}
	d := base * time.Duration(1<<uint(attempt-1))
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	// Small jitter to avoid thundering herds.
	return d + time.Duration(rand.Int63n(int64(100*time.Millisecond)))
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// tokenBucket is a simple context-aware rate limiter.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate float64, burst int) *tokenBucket {
	return &tokenBucket{rate: rate, burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (b *tokenBucket) Wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		b.last = now
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		need := (1 - b.tokens) / b.rate
		b.mu.Unlock()
		if err := sleepCtx(ctx, time.Duration(need*float64(time.Second))); err != nil {
			return err
		}
	}
}
