package crawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/akshaytheflash/antisqli/internal/httpx"
	"github.com/akshaytheflash/antisqli/internal/vulnapp"
)

func newClient(t *testing.T) *httpx.Client {
	t.Helper()
	c, err := httpx.New(httpx.Options{Timeout: 5 * time.Second, FollowRedirect: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestCrawlDiscoversLinksAndForms(t *testing.T) {
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, err := Run(ctx, newClient(t), []string{srv.URL + "/"}, Options{
		MaxDepth:    1,
		MaxPages:    20,
		SameHost:    true,
		Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Pages == 0 {
		t.Fatal("crawled no pages")
	}

	seen := map[string]bool{}
	for _, r := range res.Requests {
		seen[r.Method+" "+r.URL.Path] = true
	}
	for _, want := range []string{
		"GET /item",
		"GET /search",
		"GET /api/user",
		"POST /form",
	} {
		if !seen[want] {
			t.Errorf("missing request %s (got %v)", want, seen)
		}
	}

	for _, r := range res.Requests {
		if r.Method == http.MethodGet && r.URL.Path == "/" && r.URL.RawQuery == "" {
			t.Error("seed page without parameters should not be a scan target")
		}
	}
}

func TestCrawlSameHost(t *testing.T) {
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := Run(ctx, newClient(t), []string{srv.URL + "/"}, Options{
		MaxDepth:    2,
		MaxPages:    10,
		SameHost:    true,
		Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range res.Visited {
		if !strings.HasPrefix(v, srv.URL) {
			t.Fatalf("crawled off-host URL %s", v)
		}
	}
}

func TestNormalize(t *testing.T) {
	got := normalize("HTTPS://Example.TEST/a?b=2&a=1#frag")
	want := "https://example.test/a?a=1&b=2"
	if got != want {
		t.Fatalf("normalize = %q, want %q", got, want)
	}
}

func TestAllowedURLStaticAndExclude(t *testing.T) {
	opts := Options{SameHost: true, Exclude: []string{"logout"}}
	if allowedURL("https://example.test/logo.png", "example.test", opts, nil) {
		t.Fatal("static asset should be rejected")
	}
	if allowedURL("https://example.test/logout?x=1", "example.test", opts, nil) {
		t.Fatal("excluded URL should be rejected")
	}
	if !allowedURL("https://example.test/item?id=1", "example.test", opts, nil) {
		t.Fatal("scannable URL should be allowed")
	}
}
