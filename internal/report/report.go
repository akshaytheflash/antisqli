// Package report renders scan results as terminal output, JSON or Markdown.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/akshaytheflash/antisqli/internal/fingerprint"
	"github.com/akshaytheflash/antisqli/internal/model"
	"github.com/akshaytheflash/antisqli/internal/ui"
	"github.com/akshaytheflash/antisqli/internal/version"
	"github.com/akshaytheflash/antisqli/internal/waf"
)

// Report is the serializable outcome of a scan.
type Report struct {
	Tool       string          `json:"tool"`
	Version    string          `json:"version"`
	Target     string          `json:"target"`
	StartedAt  time.Time       `json:"started_at"`
	DurationMS int64           `json:"duration_ms"`
	Requests   int64           `json:"requests"`
	Points     int             `json:"points"`
	Techniques []string        `json:"techniques"`
	DBMS       string          `json:"dbms,omitempty"`
	WAF        waf.Result      `json:"waf"`
	Findings   []model.Finding `json:"findings"`
	Errors     []string        `json:"errors,omitempty"`
	Blocked    int64           `json:"blocked_requests,omitempty"`
}

// New builds a report shell.
func New(target string, started time.Time) *Report {
	return &Report{
		Tool:      version.Name,
		Version:   version.String(),
		Target:    target,
		StartedAt: started,
		Findings:  []model.Finding{},
	}
}

// Terminal renders a human friendly summary.
func Terminal(u *ui.UI, r *Report) {
	u.Section("Scan summary")
	u.KV("Target", r.Target)
	u.KV("Parameters", fmt.Sprintf("%d", r.Points))
	u.KV("Requests", fmt.Sprintf("%d", r.Requests))
	u.KV("Duration", formatDuration(time.Duration(r.DurationMS)*time.Millisecond))
	if r.DBMS != "" {
		u.KV("Backend", fingerprint.DisplayName(r.DBMS))
	}
	if r.WAF.Detected {
		line := r.WAF.Name
		if r.WAF.Blocked {
			line += " (requests blocked)"
		}
		u.KV("WAF", u.Yellow(line))
	}
	if len(r.Errors) > 0 {
		u.KV("Warnings", u.Yellow(fmt.Sprintf("%d", len(r.Errors))))
	}

	if len(r.Findings) == 0 {
		u.Section("Result")
		u.Success("No SQL injection detected in %d parameter(s)", r.Points)
		u.Printf("  %s", u.Dim("Try --level 2 --risk 2 --technique error,boolean,time,union for deeper coverage."))
		return
	}

	u.Section(fmt.Sprintf("Findings (%d)", len(r.Findings)))
	for i, f := range r.Findings {
		u.Printf("\n  %s %s %s", u.Status(f.Severity), u.Bold(fmt.Sprintf("%s parameter %q", f.Location, f.Parameter)), u.Dim(fmt.Sprintf("(%d/%d)", i+1, len(r.Findings))))
		u.Printf("    %s %s", u.Dim("Technique"), techniqueLabel(f.Technique))
		if f.DBMS != "" {
			u.Printf("    %s %s", u.Dim("Backend  "), fingerprint.DisplayName(f.DBMS))
		}
		u.Printf("    %s %.0f%%", u.Dim("Confidence"), f.Confidence*100)
		if f.Endpoint != "" {
			u.Printf("    %s %s", u.Dim("Endpoint "), f.Endpoint)
		}
		u.Printf("    %s %s", u.Dim("Payload  "), u.Cyan(f.Payload))
		if f.Evidence != "" {
			u.Printf("    %s %s", u.Dim("Evidence "), f.Evidence)
		}
		if v := f.Details["version"]; v != "" {
			u.Printf("    %s %s", u.Dim("Version  "), v)
		}
		if v := f.Details["columns"]; v != "" {
			u.Printf("    %s %s", u.Dim("Columns  "), v)
		}
	}

	u.Section("Remediation")
	for _, line := range []string{
		"Use parameterized queries (prepared statements) for every SQL statement.",
		"Never concatenate user input into SQL; validate types and allow-list sort columns.",
		"Apply least-privilege database accounts and disable verbose SQL errors in production.",
		"Add a WAF as defense in depth, not as a substitute for fixing the query.",
	} {
		u.Printf("  %s %s", u.Cyan("•"), line)
	}

	// Severity rollup.
	counts := map[string]int{}
	for _, f := range r.Findings {
		counts[strings.ToLower(f.Severity)]++
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	u.Printf("\n  %s %s\n", u.Bold("Total:"), strings.Join(parts, ", "))
}

func techniqueLabel(t string) string {
	switch t {
	case "error":
		return "error-based"
	case "boolean":
		return "boolean-based blind"
	case "time":
		return "time-based blind"
	case "union":
		return "UNION-based"
	}
	return t
}

// WriteJSON writes an indented JSON report.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// WriteMarkdown writes a Markdown report suitable for tickets and pull
// requests.
func WriteMarkdown(w io.Writer, r *Report) error {
	var b strings.Builder
	b.WriteString("# SQL Injection Assessment\n\n")
	fmt.Fprintf(&b, "**Target:** `%s`  \n", r.Target)
	fmt.Fprintf(&b, "**Date:** %s  \n", r.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "**Tool:** %s %s  \n", r.Tool, r.Version)
	fmt.Fprintf(&b, "**Duration:** %s  \n", formatDuration(time.Duration(r.DurationMS)*time.Millisecond))
	fmt.Fprintf(&b, "**Requests:** %d  \n", r.Requests)
	fmt.Fprintf(&b, "**Parameters tested:** %d  \n", r.Points)
	if r.DBMS != "" {
		fmt.Fprintf(&b, "**Backend:** %s  \n", fingerprint.DisplayName(r.DBMS))
	}
	if r.WAF.Detected {
		fmt.Fprintf(&b, "**WAF:** %s  \n", r.WAF.Name)
	}
	b.WriteString("\n")

	b.WriteString("## Summary\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("No SQL injection was detected.\n\n")
	} else {
		fmt.Fprintf(&b, "%d finding(s) confirmed.\n\n", len(r.Findings))
		b.WriteString("| # | Severity | Parameter | Location | Technique | Confidence |\n")
		b.WriteString("|---|----------|-----------|----------|-----------|------------|\n")
		for i, f := range r.Findings {
			fmt.Fprintf(&b, "| %d | %s | `%s` | %s | %s | %.0f%% |\n",
				i+1, strings.ToUpper(f.Severity), f.Parameter, f.Location, techniqueLabel(f.Technique), f.Confidence*100)
		}
		b.WriteString("\n")
	}

	for i, f := range r.Findings {
		fmt.Fprintf(&b, "## %d. `%s` (%s) - %s\n\n", i+1, f.Parameter, f.Location, strings.ToUpper(f.Severity))
		fmt.Fprintf(&b, "- **Endpoint:** `%s`\n", f.Endpoint)
		fmt.Fprintf(&b, "- **Technique:** %s\n", techniqueLabel(f.Technique))
		if f.DBMS != "" {
			fmt.Fprintf(&b, "- **Backend:** %s\n", fingerprint.DisplayName(f.DBMS))
		}
		fmt.Fprintf(&b, "- **Confidence:** %.0f%%\n", f.Confidence*100)
		fmt.Fprintf(&b, "- **Payload:** `%s`\n", strings.ReplaceAll(f.Payload, "`", "\\`"))
		if f.Evidence != "" {
			fmt.Fprintf(&b, "- **Evidence:** %s\n", f.Evidence)
		}
		for _, key := range []string{"version", "columns", "baseline_ms", "observed_ms", "true_payload", "false_payload"} {
			if v, ok := f.Details[key]; ok {
				fmt.Fprintf(&b, "- **%s:** `%s`\n", key, v)
			}
		}
		b.WriteString("\n")
	}

	if len(r.Errors) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "- %s\n", e)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Remediation\n\n")
	b.WriteString("1. Replace string concatenation with parameterized queries.\n")
	b.WriteString("2. Validate and allow-list identifiers such as sort columns and table names.\n")
	b.WriteString("3. Use least-privilege database users and disable detailed SQL errors in production.\n")
	b.WriteString("4. Keep a WAF as defense in depth.\n")

	_, err := io.WriteString(w, b.String())
	return err
}

// FormatFromPath infers the output format from a file extension.
func FormatFromPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".json"):
		return "json"
	case strings.HasSuffix(lower, ".md"), strings.HasSuffix(lower, ".markdown"):
		return "markdown"
	}
	return ""
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}
