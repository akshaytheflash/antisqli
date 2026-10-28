// Package model defines the shared data structures used across sqli:
// HTTP request templates, injection points, responses and findings.
package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Location identifies where a parameter lives inside an HTTP request.
type Location int

const (
	LocQuery Location = iota
	LocBodyForm
	LocBodyJSON
	LocCookie
	LocHeader
	LocPath
)

var locNames = map[Location]string{
	LocQuery:    "query",
	LocBodyForm: "body",
	LocBodyJSON: "json",
	LocCookie:   "cookie",
	LocHeader:   "header",
	LocPath:     "path",
}

// String implements fmt.Stringer.
func (l Location) String() string {
	if s, ok := locNames[l]; ok {
		return s
	}
	return "unknown"
}

// ParseLocation converts a user supplied location name into a Location.
func ParseLocation(s string) (Location, bool) {
	for k, v := range locNames {
		if strings.EqualFold(v, s) {
			return k, true
		}
	}
	return 0, false
}

// Response is a normalized HTTP response used by every technique.
type Response struct {
	Method   string      `json:"method"`
	URL      string      `json:"url"`
	Status   int         `json:"status"`
	Header   http.Header `json:"headers"`
	Body     []byte      `json:"-"`
	Duration time.Duration
	Err      error `json:"-"`
}

// Text returns the response body as a string.
func (r *Response) Text() string {
	if r == nil {
		return ""
	}
	return string(r.Body)
}

// HeaderValue returns the first value of a response header (case insensitive).
func (r *Response) HeaderValue(name string) string {
	if r == nil || r.Header == nil {
		return ""
	}
	return r.Header.Get(name)
}

// OK reports whether the request completed without a transport error.
func (r *Response) OK() bool { return r != nil && r.Err == nil }

// BodySize is a convenience accessor for the body length.
func (r *Response) BodySize() int {
	if r == nil {
		return 0
	}
	return len(r.Body)
}

// Point is a single injectable location within a request template.
type Point struct {
	Location Location
	Name     string // parameter, header or cookie name; JSON field name; path segment value
	Original string

	Method   string
	URL      *url.URL
	Header   http.Header
	Body     []byte
	BodyType string   // "form" or "json" when relevant
	JSONPath []string // for LocBodyJSON
	PathIdx  int      // for LocPath
}

// Key returns a stable identifier for the injection point.
func (p Point) Key() string {
	return fmt.Sprintf("%s:%s", p.Location, p.Name)
}

// Describe renders a human friendly description such as "GET id (query)".
func (p Point) Describe() string {
	switch p.Location {
	case LocQuery:
		return fmt.Sprintf("%s %s (query)", p.Method, p.Name)
	case LocBodyForm:
		return fmt.Sprintf("%s %s (body)", p.Method, p.Name)
	case LocBodyJSON:
		return fmt.Sprintf("%s %s (json)", p.Method, p.Name)
	case LocCookie:
		return fmt.Sprintf("cookie %s", p.Name)
	case LocHeader:
		return fmt.Sprintf("header %s", p.Name)
	case LocPath:
		return fmt.Sprintf("%s path[%d] (path)", p.Method, p.PathIdx)
	}
	return p.Name
}

// Clone returns a deep copy of the point.
func (p Point) Clone() Point {
	c := p
	c.Header = p.Header.Clone()
	c.Body = append([]byte(nil), p.Body...)
	c.JSONPath = append([]string(nil), p.JSONPath...)
	if p.URL != nil {
		u := *p.URL
		c.URL = &u
	}
	return c
}

// Inject builds an HTTP request with the injection point replaced by value.
func (p Point) Inject(value string) (*http.Request, error) {
	if p.URL == nil {
		return nil, fmt.Errorf("point %s has no URL", p.Key())
	}
	u := *p.URL
	u.Fragment = ""
	header := p.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	var body []byte

	switch p.Location {
	case LocQuery:
		q := u.Query()
		q.Set(p.Name, value)
		u.RawQuery = q.Encode()

	case LocBodyForm:
		form, err := url.ParseQuery(string(p.Body))
		if err != nil {
			return nil, fmt.Errorf("parse form body: %w", err)
		}
		form.Set(p.Name, value)
		body = []byte(form.Encode())

	case LocBodyJSON:
		newBody, err := injectJSON(p.Body, p.JSONPath, value)
		if err != nil {
			return nil, err
		}
		body = newBody

	case LocCookie:
		cookies := parseCookiePairs(header.Get("Cookie"))
		found := false
		for i := range cookies {
			if cookies[i][0] == p.Name {
				cookies[i][1] = value
				found = true
			}
		}
		if !found {
			cookies = append(cookies, [2]string{p.Name, value})
		}
		parts := make([]string, 0, len(cookies))
		for _, c := range cookies {
			parts = append(parts, c[0]+"="+c[1])
		}
		header.Set("Cookie", strings.Join(parts, "; "))

	case LocHeader:
		header.Set(p.Name, value)

	case LocPath:
		segs := splitPath(u.Path)
		if p.PathIdx < 0 || p.PathIdx >= len(segs) {
			return nil, fmt.Errorf("path index %d out of range", p.PathIdx)
		}
		segs[p.PathIdx] = value
		u.Path = joinPath(segs)

	default:
		return nil, fmt.Errorf("unsupported location %s", p.Location)
	}

	payloadBody := body
	if payloadBody == nil {
		payloadBody = p.Body
	}
	var bodyReader io.Reader
	if payloadBody != nil {
		bodyReader = bytes.NewReader(payloadBody)
	}

	method := p.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, u.String(), bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header = header
	if payloadBody != nil && req.Header.Get("Content-Length") == "" {
		req.ContentLength = int64(len(payloadBody))
	}
	return req, nil
}

// WithBaseURL returns a copy of the point bound to a new base URL, preserving
// the path and query of the original.
func (p Point) WithBaseURL(base *url.URL) Point {
	c := p.Clone()
	u := *base
	if p.URL != nil {
		u.Path = p.URL.Path
		u.RawQuery = p.URL.RawQuery
	}
	c.URL = &u
	return c
}

func injectJSON(body []byte, path []string, value string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var root any
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("parse json body: %w", err)
	}
	if len(path) == 0 {
		return nil, fmt.Errorf("empty json path")
	}
	node := root
	for i, key := range path {
		last := i == len(path)-1
		switch container := node.(type) {
		case map[string]any:
			next, ok := container[key]
			if !ok {
				return nil, fmt.Errorf("json path %v missing key %q", path, key)
			}
			if last {
				container[key] = value
			} else {
				node = next
			}
		case []any:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(container) {
				return nil, fmt.Errorf("json path %v has invalid array index %q", path, key)
			}
			if last {
				container[idx] = value
			} else {
				node = container[idx]
			}
		default:
			return nil, fmt.Errorf("json path %v cannot descend into %T", path, node)
		}
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func parseCookiePairs(raw string) [][2]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out [][2]string
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out = append(out, [2]string{strings.TrimSpace(name), strings.TrimSpace(value)})
	}
	return out
}

func splitPath(p string) []string {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return []string{""}
	}
	return strings.Split(p, "/")
}

func joinPath(segs []string) string {
	return "/" + strings.Join(segs, "/")
}

// Finding is a confirmed injection point with supporting evidence.
type Finding struct {
	Parameter  string            `json:"parameter"`
	Location   string            `json:"location"`
	Endpoint   string            `json:"endpoint,omitempty"`
	Technique  string            `json:"technique"`
	DBMS       string            `json:"dbms,omitempty"`
	Confidence float64           `json:"confidence"`
	Severity   string            `json:"severity"`
	Payload    string            `json:"payload"`
	Evidence   string            `json:"evidence,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
	Request    string            `json:"request,omitempty"`
}

// Key returns a de-duplication key for a finding.
func (f Finding) Key() string {
	return f.Endpoint + "|" + f.Location + ":" + f.Parameter + ":" + f.Technique
}

// SortFindings orders findings by severity then parameter for stable output.
func SortFindings(fs []Finding) {
	rank := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := rank[strings.ToLower(fs[i].Severity)], rank[strings.ToLower(fs[j].Severity)]
		if ri != rj {
			return ri < rj
		}
		if fs[i].Parameter != fs[j].Parameter {
			return fs[i].Parameter < fs[j].Parameter
		}
		return fs[i].Technique < fs[j].Technique
	})
}

// SeverityFor maps a technique and confidence to a severity label.
func SeverityFor(technique string, confidence float64) string {
	switch technique {
	case "error", "union":
		if confidence >= 0.9 {
			return "critical"
		}
		return "high"
	case "boolean":
		if confidence >= 0.9 {
			return "high"
		}
		return "medium"
	case "time":
		if confidence >= 0.95 {
			return "high"
		}
		return "medium"
	}
	return "low"
}
