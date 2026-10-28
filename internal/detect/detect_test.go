package detect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/akshaytheflash/antisqli/internal/discover"
	"github.com/akshaytheflash/antisqli/internal/httpx"
	"github.com/akshaytheflash/antisqli/internal/payload"
	"github.com/akshaytheflash/antisqli/internal/vulnapp"
)

func scanPath(t *testing.T, path string, opts Options) *Result {
	t.Helper()
	srv := httptest.NewServer(vulnapp.Handler())
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	points := discover.PointsFromRequest(req, discover.Options{Level: 1})
	if len(points) == 0 {
		t.Fatalf("no injection points discovered for %s", path)
	}

	client, err := httpx.New(httpx.Options{
		Timeout:        15 * time.Second,
		Retries:        0,
		FollowRedirect: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)

	if opts.Samples == 0 {
		opts.Samples = 2
	}
	if opts.Concurrency == 0 {
		opts.Concurrency = 4
	}
	if opts.MaxRequests == 0 {
		opts.MaxRequests = 500
	}
	eng, err := New(client, opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return eng.Scan(ctx, points)
}

func TestErrorBasedDetection(t *testing.T) {
	res := scanPath(t, "/item?id=1", Options{
		Techniques: []payload.Technique{payload.Error},
		Level:      1,
	})
	if len(res.Findings) == 0 {
		t.Fatal("expected an error-based finding")
	}
	f := res.Findings[0]
	if f.Technique != "error" {
		t.Fatalf("technique = %s", f.Technique)
	}
	if f.DBMS != "mysql" {
		t.Fatalf("dbms = %s", f.DBMS)
	}
	if f.Details["version"] != "8.0.32" {
		t.Fatalf("version = %q", f.Details["version"])
	}
	if f.Confidence < 0.9 {
		t.Fatalf("confidence = %.2f", f.Confidence)
	}
}

func TestBooleanBasedDetection(t *testing.T) {
	res := scanPath(t, "/search?q=apple", Options{
		Techniques: []payload.Technique{payload.Boolean},
		Level:      1,
	})
	if len(res.Findings) == 0 {
		t.Fatal("expected a boolean-based finding")
	}
	if res.Findings[0].Technique != "boolean" {
		t.Fatalf("technique = %s", res.Findings[0].Technique)
	}
	if res.Findings[0].Confidence < 0.7 {
		t.Fatalf("confidence = %.2f", res.Findings[0].Confidence)
	}
}

func TestUnionBasedDetection(t *testing.T) {
	res := scanPath(t, "/item?id=1", Options{
		Techniques: []payload.Technique{payload.Union},
		Level:      1,
	})
	if len(res.Findings) == 0 {
		t.Fatal("expected a union-based finding")
	}
	f := res.Findings[0]
	if f.Technique != "union" {
		t.Fatalf("technique = %s", f.Technique)
	}
	if f.Details["columns"] != "2" {
		t.Fatalf("columns = %q", f.Details["columns"])
	}
	if f.Details["version"] != "8.0.32" {
		t.Fatalf("version = %q", f.Details["version"])
	}
}

func TestTimeBasedDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}
	start := time.Now()
	res := scanPath(t, "/item?id=1", Options{
		Techniques: []payload.Technique{payload.Time},
		Level:      1,
		Samples:    2,
		TimeDelay:  1,
	})
	if len(res.Findings) == 0 {
		t.Fatal("expected a time-based finding")
	}
	if res.Findings[0].Technique != "time" {
		t.Fatalf("technique = %s", res.Findings[0].Technique)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("timing scan took too long: %s", elapsed)
	}
}

func TestCleanTargetHasNoFindings(t *testing.T) {
	res := scanPath(t, "/clean?id=1", Options{
		Techniques: []payload.Technique{payload.Error, payload.Boolean, payload.Union},
		Level:      1,
	})
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
}

func TestStaticPageHasNoFindings(t *testing.T) {
	res := scanPath(t, "/?id=1", Options{
		Techniques: []payload.Technique{payload.Error, payload.Boolean},
		Level:      1,
	})
	if len(res.Findings) != 0 {
		t.Fatalf("expected no findings, got %+v", res.Findings)
	}
}

func TestBudgetIsEnforced(t *testing.T) {
	res := scanPath(t, "/clean?id=1", Options{
		Techniques:  []payload.Technique{payload.Union},
		Level:       1,
		MaxRequests: 3,
	})
	if res.Requests > 5 {
		t.Fatalf("budget exceeded: %d requests", res.Requests)
	}
}
