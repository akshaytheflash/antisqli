package detect

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/akshaytheflash/antisqli/internal/fingerprint"
	"github.com/akshaytheflash/antisqli/internal/model"
	"github.com/akshaytheflash/antisqli/internal/payload"
	"github.com/akshaytheflash/antisqli/internal/waf"
)

// checkError looks for database error messages that appear only after
// injecting a syntax-breaking or version-reading payload.
func (e *Engine) checkError(ctx context.Context, p model.Point, base *Baseline) []model.Finding {
	baselineSigs := signatureSet(base.Body)
	dbmsHint := e.targetDBMS()

	for _, ep := range payload.ErrorPayloads(dbmsHint) {
		if ctx.Err() != nil || e.budgetExceeded() {
			return nil
		}
		ex, err := e.send(ctx, p, ep.Value)
		if err != nil {
			if errors.Is(err, ErrBudget) {
				return nil
			}
			continue
		}
		if ex.resp == nil || ex.resp.Err != nil {
			continue
		}
		if waf.Blocked(ex.resp) {
			e.blocked.Add(1)
			continue
		}

		matches := fingerprint.Analyze(ex.resp.Text())
		var fresh []fingerprint.Match
		for _, m := range matches {
			if baselineSigs[m.DBMS+"|"+m.Evidence] {
				continue
			}
			fresh = append(fresh, m)
		}
		if len(fresh) == 0 {
			continue
		}

		best := fresh[0]
		conf := 0.0
		switch {
		case best.DBMS != "unknown":
			conf = 0.94
			e.recordDBMS(best.DBMS)
		case ex.resp.Status >= 500:
			conf = 0.80
		default:
			// A generic "syntax error" string on a 200 page is weak evidence.
			continue
		}

		version := fingerprint.VersionFrom(ex.resp.Text(), best.DBMS)
		if version == "" && best.DBMS != "unknown" {
			// Try a dedicated version-reading payload to enrich the finding.
			version = e.readVersion(ctx, p, best.DBMS)
		}
		if version != "" {
			conf = 0.98
		}
		if ep.Extract && version == "" && best.DBMS == "unknown" {
			conf -= 0.10
		}
		conf = clamp(conf, 0.5, 0.99)

		details := map[string]string{
			"signature": best.Evidence,
			"status":    fmt.Sprintf("%d", ex.resp.Status),
			"payload":   ep.Name,
		}
		if version != "" {
			details["version"] = version
		}
		if line := firstErrorLine(ex.resp.Text()); line != "" {
			details["message"] = line
		}

		evidence := fmt.Sprintf("%s error introduced by payload %q", best.DBMS, ep.Name)
		if version != "" {
			evidence = fmt.Sprintf("%s error leaked version %s", best.DBMS, version)
		}

		f := e.makeFinding(p, payload.Error, best.DBMS, conf, ep.Value, evidence, details, ex)
		return []model.Finding{f}
	}
	return nil
}

// readVersion tries extraction payloads for dbms to obtain a version string.
func (e *Engine) readVersion(ctx context.Context, p model.Point, dbms string) string {
	attempts := 0
	for _, ep := range payload.ErrorPayloads(dbms) {
		if !ep.Extract {
			continue
		}
		if attempts >= 2 || e.budgetExceeded() || ctx.Err() != nil {
			break
		}
		attempts++
		ex, err := e.send(ctx, p, ep.Value)
		if err != nil || ex.resp == nil || ex.resp.Err != nil {
			continue
		}
		if v := fingerprint.VersionFrom(ex.resp.Text(), dbms); v != "" {
			return v
		}
	}
	return ""
}

// signatureSet indexes the DBMS signatures already present in a body.
func signatureSet(body string) map[string]bool {
	set := map[string]bool{}
	for _, m := range fingerprint.Analyze(body) {
		set[m.DBMS+"|"+m.Evidence] = true
	}
	return set
}

// firstErrorLine extracts a short, human readable error line from a response.
func firstErrorLine(body string) string {
	keywords := []string{"error", "warning", "exception", "syntax", "ORA-", "SQLSTATE"}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(stripTags(line))
		if len(line) < 8 || len(line) > 300 {
			continue
		}
		lower := strings.ToLower(line)
		for _, kw := range keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				return line
			}
		}
	}
	return ""
}

func stripTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		switch {
		case r == '<':
			inTag = true
		case r == '>':
			inTag = false
		case !inTag:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
