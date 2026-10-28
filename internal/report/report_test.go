package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/akshaytheflash/antisqli/internal/model"
)

func sample() *Report {
	r := New("https://example.test/item?id=1", time.Now())
	r.DurationMS = 1234
	r.Requests = 42
	r.Points = 2
	r.DBMS = "mysql"
	r.Findings = []model.Finding{{
		Parameter:  "id",
		Location:   "query",
		Endpoint:   "GET https://example.test/item",
		Technique:  "error",
		DBMS:       "mysql",
		Confidence: 0.98,
		Severity:   "critical",
		Payload:    "'",
		Evidence:   "mysql error introduced",
		Details:    map[string]string{"version": "8.0.32"},
	}}
	return r
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if decoded["tool"] != "sqli" {
		t.Fatalf("tool = %v", decoded["tool"])
	}
	findings, ok := decoded["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("findings = %v", decoded["findings"])
	}
}

func TestWriteMarkdown(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, sample()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"# SQL Injection Assessment",
		"| 1 | CRITICAL | `id` |",
		"## 1. `id` (query) - CRITICAL",
		"**Payload:** `'`",
		"## Remediation",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n%s", want, out)
		}
	}
}

func TestWriteMarkdownNoFindings(t *testing.T) {
	r := sample()
	r.Findings = nil
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No SQL injection was detected.") {
		t.Fatalf("unexpected output:\n%s", buf.String())
	}
}

func TestFormatFromPath(t *testing.T) {
	cases := map[string]string{
		"a.json":     "json",
		"a.md":       "markdown",
		"a.markdown": "markdown",
		"a.txt":      "",
		"a":          "",
	}
	for in, want := range cases {
		if got := FormatFromPath(in); got != want {
			t.Errorf("FormatFromPath(%q) = %q, want %q", in, got, want)
		}
	}
}
