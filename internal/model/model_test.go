package model

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestInjectQuery(t *testing.T) {
	p := Point{
		Location: LocQuery,
		Name:     "id",
		Method:   http.MethodGet,
		URL:      mustURL(t, "https://example.test/item?id=1&page=2"),
		Header:   http.Header{},
	}
	req, err := p.Inject("1' AND 1=1-- -")
	if err != nil {
		t.Fatal(err)
	}
	q := req.URL.Query()
	if q.Get("id") != "1' AND 1=1-- -" {
		t.Fatalf("id = %q", q.Get("id"))
	}
	if q.Get("page") != "2" {
		t.Fatalf("page parameter lost: %q", q.Get("page"))
	}
}

func TestInjectForm(t *testing.T) {
	p := Point{
		Location: LocBodyForm,
		Name:     "user",
		Method:   http.MethodPost,
		URL:      mustURL(t, "https://example.test/login"),
		Header:   http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
		Body:     []byte("user=alice&pass=secret"),
	}
	req, err := p.Inject("bob'-- -")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(req.Body)
	form, _ := url.ParseQuery(string(data))
	if form.Get("user") != "bob'-- -" || form.Get("pass") != "secret" {
		t.Fatalf("unexpected form: %s", data)
	}
}

func TestInjectJSON(t *testing.T) {
	body := `{"user":{"name":"alice"},"list":[{"c":"y"}],"active":true}`
	p := Point{
		Location: LocBodyJSON,
		Name:     "user.name",
		Method:   http.MethodPost,
		URL:      mustURL(t, "https://example.test/api"),
		Header:   http.Header{"Content-Type": []string{"application/json"}},
		Body:     []byte(body),
		JSONPath: []string{"user", "name"},
	}
	req, err := p.Inject("PAYLOAD")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(req.Body)
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON: %v (%s)", err, data)
	}
	if got["user"].(map[string]any)["name"] != "PAYLOAD" {
		t.Fatalf("nested value not injected: %s", data)
	}
	if got["active"] != true {
		t.Fatalf("unrelated field lost: %s", data)
	}

	// Array element.
	p.JSONPath = []string{"list", "0", "c"}
	p.Name = "list.0.c"
	req, err = p.Inject("Z")
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(req.Body)
	if !strings.Contains(string(data), `"c":"Z"`) {
		t.Fatalf("array element not injected: %s", data)
	}
}

func TestInjectCookie(t *testing.T) {
	p := Point{
		Location: LocCookie,
		Name:     "session",
		Method:   http.MethodGet,
		URL:      mustURL(t, "https://example.test/"),
		Header:   http.Header{"Cookie": []string{"session=abc; theme=dark"}},
	}
	req, err := p.Inject("x'y")
	if err != nil {
		t.Fatal(err)
	}
	cookie := req.Header.Get("Cookie")
	if !strings.Contains(cookie, "session=x'y") || !strings.Contains(cookie, "theme=dark") {
		t.Fatalf("unexpected cookie: %q", cookie)
	}
}

func TestInjectHeader(t *testing.T) {
	p := Point{
		Location: LocHeader,
		Name:     "X-Forwarded-For",
		Method:   http.MethodGet,
		URL:      mustURL(t, "https://example.test/"),
		Header:   http.Header{"X-Forwarded-For": []string{"127.0.0.1"}},
	}
	req, err := p.Inject("1' OR 1=1-- -")
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Forwarded-For"); got != "1' OR 1=1-- -" {
		t.Fatalf("header = %q", got)
	}
}

func TestInjectPath(t *testing.T) {
	p := Point{
		Location: LocPath,
		Name:     "42",
		Method:   http.MethodGet,
		URL:      mustURL(t, "https://example.test/users/42/profile"),
		Header:   http.Header{},
		PathIdx:  1,
	}
	req, err := p.Inject("x y")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Path != "/users/x y/profile" {
		t.Fatalf("path = %q", req.URL.Path)
	}
}

func TestInjectMissingJSONKey(t *testing.T) {
	p := Point{
		Location: LocBodyJSON,
		Method:   http.MethodPost,
		URL:      mustURL(t, "https://example.test/api"),
		Header:   http.Header{},
		Body:     []byte(`{"a":1}`),
		JSONPath: []string{"nope"},
	}
	if _, err := p.Inject("x"); err == nil {
		t.Fatal("expected error for missing key")
	}
}

func TestFindingSorting(t *testing.T) {
	fs := []Finding{
		{Parameter: "b", Severity: "medium"},
		{Parameter: "a", Severity: "critical"},
		{Parameter: "c", Severity: "high"},
	}
	SortFindings(fs)
	if fs[0].Severity != "critical" || fs[1].Severity != "high" || fs[2].Severity != "medium" {
		t.Fatalf("unexpected order: %+v", fs)
	}
}

func TestSeverityFor(t *testing.T) {
	if got := SeverityFor("error", 0.95); got != "critical" {
		t.Fatalf("error/high confidence = %q", got)
	}
	if got := SeverityFor("boolean", 0.7); got != "medium" {
		t.Fatalf("boolean/low confidence = %q", got)
	}
}
