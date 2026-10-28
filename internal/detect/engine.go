// Package detect implements SQL injection detection techniques and the scan
// orchestration engine.
package detect

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/akshaytheflash/antisqli/internal/fingerprint"
	"github.com/akshaytheflash/antisqli/internal/httpx"
	"github.com/akshaytheflash/antisqli/internal/model"
	"github.com/akshaytheflash/antisqli/internal/payload"
	"github.com/akshaytheflash/antisqli/internal/waf"
)

// ErrBudget is returned when the configured request budget is exhausted.
var ErrBudget = errors.New("request budget exhausted")

// Options configures a scan.
type Options struct {
	Techniques  []payload.Technique
	Level       int
	Risk        int
	DBMS        string
	Concurrency int
	Samples     int
	TimeDelay   int
	MaxRequests int64
	Thorough    bool
	Tampers     []string
	Progress    func(phase string, done, total int, point model.Point)
	Debugf      func(format string, args ...any)
}

// Result is the outcome of a scan.
type Result struct {
	Findings []model.Finding
	DBMS     string
	WAF      waf.Result
	Requests int64
	Points   int
	Duration time.Duration
	Errors   []string
	Blocked  int64
}

// Engine orchestrates detection across injection points.
type Engine struct {
	client *httpx.Client
	opts   Options

	spent    atomic.Int64
	blocked  atomic.Int64
	mu       sync.Mutex
	dbms     string
	wafRes   waf.Result
	errors   []string
	cancelMu sync.Mutex
}

// exchange pairs a request with its response.
type exchange struct {
	req  *http.Request
	resp *model.Response
}

// New creates an Engine.
func New(client *httpx.Client, opts Options) (*Engine, error) {
	if client == nil {
		return nil, fmt.Errorf("nil http client")
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.Samples < 2 {
		opts.Samples = 3
	}
	if opts.Level <= 0 {
		opts.Level = 1
	}
	if opts.Risk <= 0 {
		opts.Risk = 1
	}
	if opts.TimeDelay <= 0 {
		opts.TimeDelay = 5
	}
	for _, t := range opts.Tampers {
		if !payload.ValidateTamper(t) {
			return nil, fmt.Errorf("unknown tamper %q", t)
		}
	}
	if len(opts.Techniques) == 0 {
		opts.Techniques = []payload.Technique{payload.Error, payload.Boolean, payload.Time}
	}
	return &Engine{client: client, opts: opts}, nil
}

// Scan runs detection against the given points.
func (e *Engine) Scan(ctx context.Context, points []model.Point) *Result {
	start := time.Now()
	points = preparePoints(points)
	res := &Result{Points: len(points)}

	if len(points) == 0 {
		res.Duration = time.Since(start)
		return res
	}

	baselines := e.collectBaselines(ctx, points)
	hasTime := containsTechnique(e.opts.Techniques, payload.Time)
	hasStatic := containsTechnique(e.opts.Techniques, payload.Error) ||
		containsTechnique(e.opts.Techniques, payload.Boolean) ||
		containsTechnique(e.opts.Techniques, payload.Union)

	findings := map[string]model.Finding{}
	var findMu sync.Mutex
	confirmed := make([]bool, len(points))

	if hasStatic {
		e.runStatic(ctx, points, baselines, confirmed, &findMu, findings, res)
	}

	// Time-based checks are serialized: concurrent traffic would invalidate
	// latency measurements.
	if hasTime {
		e.runTiming(ctx, points, baselines, confirmed, &findMu, findings, res)
	}

	for _, f := range findings {
		res.Findings = append(res.Findings, f)
	}
	model.SortFindings(res.Findings)
	res.Requests = e.spent.Load()
	res.Blocked = e.blocked.Load()
	res.Duration = time.Since(start)
	res.Errors = append(res.Errors, e.errors...)
	e.mu.Lock()
	res.DBMS = e.dbms
	res.WAF = e.wafRes
	e.mu.Unlock()
	return res
}

func (e *Engine) runStatic(ctx context.Context, points []model.Point, baselines []*Baseline, confirmed []bool, findMu *sync.Mutex, findings map[string]model.Finding, res *Result) {
	workers := e.opts.Concurrency
	if workers > len(points) {
		workers = len(points)
	}
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	var done atomic.Int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				base := baselines[idx]
				if base == nil {
					continue
				}
				found := e.checkStatic(ctx, points[idx], base)
				if len(found) > 0 {
					findMu.Lock()
					for _, f := range found {
						findings[f.Key()] = f
					}
					confirmed[idx] = true
					findMu.Unlock()
				}
				if e.opts.Progress != nil {
					e.opts.Progress("static", int(done.Add(1)), len(points), points[idx])
				}
			}
		}()
	}
	for i := range points {
		if ctx.Err() != nil {
			break
		}
		if e.budgetExceeded() {
			e.addError(ErrBudget.Error())
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
}

func (e *Engine) runTiming(ctx context.Context, points []model.Point, baselines []*Baseline, confirmed []bool, findMu *sync.Mutex, findings map[string]model.Finding, res *Result) {
	for i, p := range points {
		if ctx.Err() != nil {
			return
		}
		if e.budgetExceeded() {
			e.addError(ErrBudget.Error())
			return
		}
		base := baselines[i]
		if base == nil {
			continue
		}
		if confirmed[i] && !e.opts.Thorough {
			continue
		}
		found := e.checkTime(ctx, p, base)
		if len(found) > 0 {
			findMu.Lock()
			for _, f := range found {
				findings[f.Key()] = f
			}
			findMu.Unlock()
		}
		if e.opts.Progress != nil {
			e.opts.Progress("time", i+1, len(points), p)
		}
	}
}

func (e *Engine) collectBaselines(ctx context.Context, points []model.Point) []*Baseline {
	baselines := make([]*Baseline, len(points))
	workers := e.opts.Concurrency
	if workers > 10 {
		workers = 10
	}
	if workers > len(points) {
		workers = len(points)
	}
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				p := points[idx]
				samples := make([]*model.Response, 0, e.opts.Samples)
				var lastErr error
				for s := 0; s < e.opts.Samples; s++ {
					ex, err := e.send(ctx, p, p.Original)
					if err != nil {
						lastErr = err
						if errors.Is(err, ErrBudget) {
							break
						}
						continue
					}
					if ex.resp.Err != nil {
						lastErr = ex.resp.Err
						continue
					}
					samples = append(samples, ex.resp)
					mu.Lock()
					if !e.wafRes.Detected {
						if r := waf.Detect(ex.resp); r.Detected {
							e.wafRes = r
						}
					}
					mu.Unlock()
					if waf.Blocked(ex.resp) {
						mu.Lock()
						e.blocked.Add(1)
						mu.Unlock()
						break
					}
				}
				if len(samples) == 0 {
					msg := fmt.Sprintf("baseline failed for %s", p.Describe())
					if lastErr != nil {
						msg += ": " + lastErr.Error()
					}
					e.addError(msg)
					continue
				}
				if samples[0].Status >= 500 {
					e.addError(fmt.Sprintf("baseline returned %d for %s", samples[0].Status, p.Describe()))
					continue
				}
				baselines[idx] = newBaseline(samples)
			}
		}()
	}
	for i := range points {
		if ctx.Err() != nil {
			break
		}
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return baselines
}

// checkStatic runs error, boolean and union techniques for one point.
func (e *Engine) checkStatic(ctx context.Context, p model.Point, base *Baseline) []model.Finding {
	var out []model.Finding
	for _, tech := range e.opts.Techniques {
		if ctx.Err() != nil || e.budgetExceeded() {
			return out
		}
		var found []model.Finding
		switch tech {
		case payload.Error:
			found = e.checkError(ctx, p, base)
		case payload.Boolean:
			found = e.checkBoolean(ctx, p, base)
		case payload.Union:
			found = e.checkUnion(ctx, p, base)
		}
		out = append(out, found...)
		if len(out) > 0 && !e.opts.Thorough {
			return out
		}
	}
	return out
}

// send injects value into p, applies tampers and performs the request.
func (e *Engine) send(ctx context.Context, p model.Point, value string) (*exchange, error) {
	if e.budgetExceeded() {
		return nil, ErrBudget
	}
	tampered, err := payload.Apply(value, e.opts.Tampers)
	if err != nil {
		return nil, err
	}
	req, err := p.Inject(tampered)
	if err != nil {
		return nil, err
	}
	resp, doErr := e.client.Do(ctx, req)
	e.spent.Add(1)
	ex := &exchange{req: req, resp: resp}
	if doErr != nil {
		return ex, doErr
	}
	return ex, nil
}

func (e *Engine) budgetExceeded() bool {
	max := e.opts.MaxRequests
	return max > 0 && e.spent.Load() >= max
}

func (e *Engine) recordDBMS(name string) {
	if name == "" || name == "unknown" {
		return
	}
	name = normalizeDBMS(name)
	e.mu.Lock()
	if e.dbms == "" {
		e.dbms = name
	}
	e.mu.Unlock()
}

func (e *Engine) targetDBMS() string {
	if e.opts.DBMS != "" {
		return normalizeDBMS(e.opts.DBMS)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dbms
}

func (e *Engine) addError(msg string) {
	if msg == "" {
		return
	}
	e.mu.Lock()
	for _, existing := range e.errors {
		if existing == msg {
			e.mu.Unlock()
			return
		}
	}
	e.errors = append(e.errors, msg)
	e.mu.Unlock()
}

func (e *Engine) debug(format string, args ...any) {
	if e.opts.Debugf != nil {
		e.opts.Debugf(format, args...)
	}
}

func (e *Engine) makeFinding(p model.Point, tech payload.Technique, dbms string, conf float64, value, evidence string, details map[string]string, ex *exchange) model.Finding {
	endpoint := p.Method + " " + p.URL.Scheme + "://" + p.URL.Host + p.URL.Path
	f := model.Finding{
		Parameter:  p.Name,
		Location:   p.Location.String(),
		Endpoint:   endpoint,
		Technique:  string(tech),
		DBMS:       dbms,
		Confidence: round2(conf),
		Severity:   model.SeverityFor(string(tech), conf),
		Payload:    value,
		Evidence:   evidence,
		Details:    details,
	}
	if ex != nil && ex.req != nil {
		f.Request = httpx.DumpRequest(ex.req)
	}
	return f
}

func preparePoints(points []model.Point) []model.Point {
	seen := map[string]bool{}
	out := make([]model.Point, 0, len(points))
	for _, p := range points {
		if p.URL == nil || p.Name == "" {
			continue
		}
		key := p.Key() + "|" + p.URL.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi := payload.Priority(out[i].Name)
		pj := payload.Priority(out[j].Name)
		if pi != pj {
			return pi > pj
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}

func containsTechnique(ts []payload.Technique, want payload.Technique) bool {
	for _, t := range ts {
		if t == want {
			return true
		}
	}
	return false
}

func normalizeDBMS(s string) string {
	return fingerprint.NormalizeDBMS(s)
}
