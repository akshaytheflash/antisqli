package rawreq

import (
	"io"
	"strings"
	"testing"
)

func TestParseRaw(t *testing.T) {
	raw := "POST /login?next=%2Fhome HTTP/1.1\r\nHost: example.test:8443\r\nContent-Type: application/x-www-form-urlencoded\r\nX-Test: one\r\nX-Test: two\r\n\r\nuser=alice&pass=secret"
	req, err := ParseRaw([]byte(raw), "https")
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" {
		t.Fatalf("method = %s", req.Method)
	}
	if req.URL.String() != "https://example.test:8443/login?next=%2Fhome" {
		t.Fatalf("url = %s", req.URL.String())
	}
	if got := req.Header.Values("X-Test"); len(got) != 2 {
		t.Fatalf("duplicate headers lost: %v", got)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != "user=alice&pass=secret" {
		t.Fatalf("body = %q", body)
	}
}

func TestParseRawAbsoluteTarget(t *testing.T) {
	raw := "GET https://example.test/a?b=1 HTTP/1.1\nHost: ignored.test\n\n"
	req, err := ParseRaw([]byte(raw), "http")
	if err != nil {
		t.Fatal(err)
	}
	if req.URL.Host != "example.test" {
		t.Fatalf("host = %s", req.URL.Host)
	}
}

func TestParseRawMissingHost(t *testing.T) {
	if _, err := ParseRaw([]byte("GET /a HTTP/1.1\n\n"), "https"); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestParseCurl(t *testing.T) {
	cmd := `curl 'https://example.test/api?x=1' -X POST -H 'Content-Type: application/json' -H "Authorization: Bearer abc" -d '{"name":"alice"}'`
	req, insecure, err := ParseCurl(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if insecure {
		t.Fatal("did not expect insecure")
	}
	if req.Method != "POST" {
		t.Fatalf("method = %s", req.Method)
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("content type = %q", req.Header.Get("Content-Type"))
	}
	if req.Header.Get("Authorization") != "Bearer abc" {
		t.Fatalf("authorization = %q", req.Header.Get("Authorization"))
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"name":"alice"}` {
		t.Fatalf("body = %q", body)
	}
}

func TestParseCurlInsecureAndCookies(t *testing.T) {
	req, insecure, err := ParseCurl(`curl -k -b "a=1; b=2" https://example.test/`)
	if err != nil {
		t.Fatal(err)
	}
	if !insecure {
		t.Fatal("expected insecure")
	}
	if req.Header.Get("Cookie") != "a=1; b=2" {
		t.Fatalf("cookie = %q", req.Header.Get("Cookie"))
	}
}

func TestParseCurlNoURL(t *testing.T) {
	if _, _, err := ParseCurl(`curl -X GET`); err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestShellSplit(t *testing.T) {
	got, err := shellSplit(`curl 'a b' "c\"d" e\ f`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"curl", "a b", `c"d`, "e f"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseHeaders(t *testing.T) {
	h, err := ParseHeaders([]string{"A: 1", "B: 2"})
	if err != nil {
		t.Fatal(err)
	}
	if h.Get("A") != "1" || h.Get("B") != "2" {
		t.Fatalf("unexpected headers: %v", h)
	}
	if _, err := ParseHeaders([]string{"broken"}); err == nil {
		t.Fatal("expected error for malformed header")
	}
}

func TestParseCookies(t *testing.T) {
	c := ParseCookies("a=1; b=2")
	if c["a"] != "1" || c["b"] != "2" {
		t.Fatalf("unexpected cookies: %v", c)
	}
}

func TestParseRawCRLFBodyPreserved(t *testing.T) {
	raw := "POST /x HTTP/1.1\r\nHost: h\r\n\r\na=1\r\nb=2"
	req, err := ParseRaw([]byte(raw), "http")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "a=1") {
		t.Fatalf("body lost: %q", body)
	}
}
