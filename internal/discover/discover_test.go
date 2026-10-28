package discover

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/akshaytheflash/antisqli/internal/model"
)

const testHTML = `<!doctype html><html><head><title>t</title>
<script>var x = "<a href='/nope'>";</script></head><body>
<a href="/a?x=1">A</a>
<a href="javascript:void(0)">no</a>
<a href="#frag">no</a>
<a href="https://other.test/b">external</a>
<form method="post" action="/login">
  <input name="user" value="u">
  <input type="password" name="pass">
  <input type="submit" name="go" value="Go">
  <input type="file" name="upload">
  <textarea name="bio">hi</textarea>
  <select name="role"><option>admin</option></select>
</form>
</body></html>`

func TestParseHTML(t *testing.T) {
	base, _ := url.Parse("https://example.test/")
	page := ParseHTML([]byte(testHTML), base)

	if len(page.Links) != 2 {
		t.Fatalf("expected 2 links, got %d: %v", len(page.Links), page.Links)
	}
	want := map[string]bool{
		"https://example.test/a?x=1": true,
		"https://other.test/b":       true,
	}
	for _, l := range page.Links {
		delete(want, l)
	}
	if len(want) != 0 {
		t.Fatalf("missing links: %v (got %v)", want, page.Links)
	}

	if len(page.Forms) != 1 {
		t.Fatalf("expected 1 form, got %d", len(page.Forms))
	}
	f := page.Forms[0]
	if f.Action != "https://example.test/login" || f.Method != "POST" {
		t.Fatalf("unexpected form: %+v", f)
	}
	names := map[string]string{}
	for _, in := range f.Inputs {
		names[in.Name] = in.Type
	}
	for _, wantName := range []string{"user", "pass", "bio", "role"} {
		if _, ok := names[wantName]; !ok {
			t.Errorf("missing input %q in %v", wantName, names)
		}
	}
	if _, ok := names["go"]; ok {
		t.Error("submit input should be skipped")
	}
	if _, ok := names["upload"]; ok {
		t.Error("file input should be skipped")
	}
}

func TestFormsToRequestsGET(t *testing.T) {
	f := Form{
		Action: "https://example.test/search",
		Method: "GET",
		Inputs: []Input{{Name: "q", Value: "apple"}, {Name: "page", Value: "1"}},
	}
	req, err := FormsToRequests(f)
	if err != nil {
		t.Fatal(err)
	}
	q := req.URL.Query()
	if q.Get("q") != "apple" || q.Get("page") != "1" {
		t.Fatalf("unexpected query: %s", req.URL.RawQuery)
	}
}

func TestPointsFromRequestQuery(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.test/item?id=1&name=bob", nil)
	req.Header.Set("Cookie", "session=abc; theme=dark")
	points := PointsFromRequest(req, Options{Level: 1})

	got := map[string]string{}
	for _, p := range points {
		got[p.Location.String()+":"+p.Name] = p.Original
	}
	if got["query:id"] != "1" || got["query:name"] != "bob" {
		t.Fatalf("query points missing: %v", got)
	}
	if got["cookie:session"] != "abc" || got["cookie:theme"] != "dark" {
		t.Fatalf("cookie points missing: %v", got)
	}
}

func TestPointsFromRequestFormAndFilter(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.test/login", strings.NewReader("user=alice&pass=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	points := PointsFromRequest(req, Options{Level: 1, Params: []string{"user"}})
	if len(points) != 1 {
		t.Fatalf("expected 1 filtered point, got %d", len(points))
	}
	if points[0].Location != model.LocBodyForm || points[0].Name != "user" {
		t.Fatalf("unexpected point: %+v", points[0])
	}

	points = PointsFromRequest(req, Options{Level: 1, Skip: []string{"pass"}})
	if len(points) != 1 || points[0].Name != "user" {
		t.Fatalf("skip filter failed: %+v", points)
	}
}

func TestPointsFromJSON(t *testing.T) {
	body := `{"user":{"name":"alice"},"tags":["a","b"],"active":true}`
	req, _ := http.NewRequest("POST", "https://example.test/api", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	paths, err := JSONPaths([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, p := range paths {
		found[strings.Join(p, ".")] = true
	}
	for _, want := range []string{"user.name", "tags.0", "tags.1", "active"} {
		if !found[want] {
			t.Errorf("missing JSON path %q in %v", want, found)
		}
	}

	points := PointsFromRequest(req, Options{Level: 1})
	if len(points) != 4 {
		t.Fatalf("expected 4 JSON points, got %d", len(points))
	}
}

func TestPointsFromPathSegments(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://example.test/users/42/profile", nil)
	points := PointsFromRequest(req, Options{Level: 2, PathSegs: true})
	if len(points) != 3 {
		t.Fatalf("expected 3 path points, got %d", len(points))
	}
	if points[0].PathIdx != 0 || points[1].Name != "42" {
		t.Fatalf("unexpected path points: %+v", points)
	}
}
