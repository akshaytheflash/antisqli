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

const unionMarker = "sqliMark7x"

// checkUnion determines whether a UNION SELECT can be appended to the query
// and, if so, uses it to read the database version.
func (e *Engine) checkUnion(ctx context.Context, p model.Point, base *Baseline) []model.Finding {
	prefixes := []string{"'", ""}
	if e.opts.Level >= 2 {
		prefixes = append(prefixes, "\"", "')")
	}
	dbms := e.targetDBMS()

	for _, prefix := range prefixes {
		if ctx.Err() != nil || e.budgetExceeded() {
			return nil
		}
		cols := e.unionColumns(ctx, p, base, prefix)
		if cols < 1 {
			continue
		}
		e.debug("union: %s has %d columns with prefix %q", p.Describe(), cols, prefix)

		markerPayload := payload.UnionSelect(prefix, cols, unionMarker, dbms)
		ex, err := e.send(ctx, p, markerPayload)
		if err != nil {
			if errors.Is(err, ErrBudget) {
				return nil
			}
			continue
		}
		if ex.resp == nil || ex.resp.Err != nil || waf.Blocked(ex.resp) {
			continue
		}
		if !strings.Contains(ex.resp.Text(), unionMarker) {
			continue
		}

		conf := 0.95
		version := ""
		versionPayload := payload.UnionVersion(prefix, cols, dbms)
		vex, err := e.send(ctx, p, versionPayload)
		if err == nil && vex.resp != nil && vex.resp.Err == nil {
			version = fingerprint.VersionFrom(vex.resp.Text(), dbms)
			if version == "" && dbms == "" {
				version = fingerprint.VersionFrom(vex.resp.Text(), "mysql")
			}
			if version != "" {
				conf = 0.98
			}
		}

		details := map[string]string{
			"columns": fmt.Sprintf("%d", cols),
			"prefix":  prefix,
			"marker":  unionMarker,
		}
		if version != "" {
			details["version"] = version
		}
		evidence := fmt.Sprintf("UNION SELECT with %d column(s) reflected attacker-controlled data", cols)
		if version != "" {
			evidence = fmt.Sprintf("UNION SELECT works (%d columns) and leaked version %s", cols, version)
		}
		f := e.makeFinding(p, payload.Union, dbms, conf, markerPayload, evidence, details, ex)
		return []model.Finding{f}
	}
	return nil
}

// unionColumns finds the number of columns in the underlying query using
// ORDER BY. It returns 0 when the prefix is not viable.
func (e *Engine) unionColumns(ctx context.Context, p model.Point, base *Baseline, prefix string) int {
	for n := 1; n <= 12; n++ {
		if ctx.Err() != nil || e.budgetExceeded() {
			return 0
		}
		ex, err := e.send(ctx, p, payload.OrderBy(prefix, n))
		if err != nil {
			return 0
		}
		if ex.resp == nil || ex.resp.Err != nil {
			continue
		}
		if waf.Blocked(ex.resp) {
			e.blocked.Add(1)
			return 0
		}
		if e.looksLikeSQLError(ex.resp, base) {
			if n == 1 {
				return 0
			}
			return n - 1
		}
	}
	return 0
}

// looksLikeSQLError reports whether a response is a database error page that
// was not already present in the baseline.
func (e *Engine) looksLikeSQLError(resp *model.Response, base *Baseline) bool {
	if resp == nil || resp.Err != nil {
		return false
	}
	if resp.Status >= 500 {
		return true
	}
	if base != nil {
		for _, m := range fingerprint.Analyze(resp.Text()) {
			if !base.Sigs[m.DBMS+"|"+m.Evidence] {
				return true
			}
		}
	}
	if base != nil {
		sim := similarity(base, resp)
		delta := relativeLengthDelta(base.Length, len(resp.Body))
		if sim < 0.35 && delta > 0.5 {
			return true
		}
	}
	return false
}
