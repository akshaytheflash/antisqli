package detect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/akshaytheflash/antisqli/internal/model"
	"github.com/akshaytheflash/antisqli/internal/payload"
	"github.com/akshaytheflash/antisqli/internal/waf"
)

// checkBoolean compares the responses of logically true and false payloads.
// A stable difference between the two indicates boolean-based injection.
func (e *Engine) checkBoolean(ctx context.Context, p model.Point, base *Baseline) []model.Finding {
	self := selfSimilarity(base)
	pairs := payload.BooleanPairs(e.opts.Level, e.opts.Risk)

	for _, pair := range pairs {
		if ctx.Err() != nil || e.budgetExceeded() {
			return nil
		}
		trueEx, err := e.send(ctx, p, pair.True)
		if err != nil {
			if errors.Is(err, ErrBudget) {
				return nil
			}
			continue
		}
		falseEx, err := e.send(ctx, p, pair.False)
		if err != nil {
			if errors.Is(err, ErrBudget) {
				return nil
			}
			continue
		}
		if trueEx.resp == nil || falseEx.resp == nil {
			continue
		}
		if trueEx.resp.Err != nil || falseEx.resp.Err != nil {
			continue
		}
		if waf.Blocked(trueEx.resp) || waf.Blocked(falseEx.resp) {
			e.blocked.Add(1)
			continue
		}

		ok, conf, note := evaluateBoolean(base, self, trueEx.resp, falseEx.resp)
		if !ok {
			continue
		}
		e.debug("boolean candidate on %s with %s (%s)", p.Describe(), pair.Name, note)

		// Confirm with a second round; transient page changes must not create
		// false positives.
		confirmTrue, err1 := e.send(ctx, p, pair.True)
		confirmFalse, err2 := e.send(ctx, p, pair.False)
		if err1 != nil || err2 != nil || confirmTrue.resp == nil || confirmFalse.resp == nil {
			continue
		}
		ok2, conf2, note2 := evaluateBoolean(base, self, confirmTrue.resp, confirmFalse.resp)
		if !ok2 {
			continue
		}
		if conf2 > conf {
			conf = conf2
		}
		conf = clamp(conf+0.03, 0.6, 0.99)

		details := map[string]string{
			"true_payload":  pair.True,
			"false_payload": pair.False,
			"true_status":   fmt.Sprintf("%d", confirmTrue.resp.Status),
			"false_status":  fmt.Sprintf("%d", confirmFalse.resp.Status),
			"true_length":   fmt.Sprintf("%d", len(confirmTrue.resp.Body)),
			"false_length":  fmt.Sprintf("%d", len(confirmFalse.resp.Body)),
			"baseline_len":  fmt.Sprintf("%d", base.Length),
			"round1":        note,
			"round2":        note2,
		}
		evidence := fmt.Sprintf("true/false payloads produce consistently different responses (%s)", note2)
		f := e.makeFinding(p, payload.Boolean, e.targetDBMS(), conf, pair.True, evidence, details, confirmTrue)
		return []model.Finding{f}
	}
	return nil
}

// selfSimilarity measures how stable the baseline is across samples.
func selfSimilarity(base *Baseline) float64 {
	if base == nil || len(base.Samples) < 2 {
		return 1
	}
	var sum float64
	n := 0
	for i := 1; i < len(base.Samples); i++ {
		sum += similarity(base, base.Samples[i])
		n++
	}
	if n == 0 {
		return 1
	}
	return sum / float64(n)
}

// evaluateBoolean decides whether a true/false response pair is consistent
// with boolean-based SQL injection.
func evaluateBoolean(base *Baseline, self float64, trueResp, falseResp *model.Response) (bool, float64, string) {
	trueSim := similarity(base, trueResp)
	falseSim := similarity(base, falseResp)
	trueDelta := relativeLengthDelta(base.Length, len(trueResp.Body))
	falseDelta := relativeLengthDelta(base.Length, len(falseResp.Body))
	sameStatus := trueResp.Status == base.Status

	// Threshold adapts to how noisy the page is.
	stable := math.Max(0.80, self-0.06)

	// Normal orientation: the TRUE payload reproduces the baseline, the FALSE
	// payload changes it.
	trueMatches := sameStatus && (trueSim >= stable || (trueDelta < 0.03 && base.Length > 200))
	falseDiffers := falseSim <= trueSim-0.12 || falseDelta > 0.20 ||
		(falseResp.Status != base.Status && falseResp.Status >= 400)

	if trueMatches && falseDiffers {
		gap := math.Max(trueSim-falseSim, falseDelta-trueDelta)
		conf := clamp(0.62+gap*1.2, 0.62, 0.97)
		note := fmt.Sprintf("sim %.2f vs %.2f, len delta %.0f%% vs %.0f%%",
			trueSim, falseSim, trueDelta*100, falseDelta*100)
		return true, conf, note
	}

	// Inverted orientation (common with OR-based payloads): the FALSE payload
	// matches the baseline while TRUE expands the result set.
	falseMatches := falseResp.Status == base.Status && (falseSim >= stable || falseDelta < 0.03)
	trueDiffers := trueSim <= falseSim-0.12 || trueDelta > 0.20
	if falseMatches && trueDiffers {
		gap := math.Max(falseSim-trueSim, trueDelta-falseDelta)
		conf := clamp(0.58+gap*1.1, 0.58, 0.92)
		note := fmt.Sprintf("inverted: sim %.2f vs %.2f, len delta %.0f%% vs %.0f%%",
			trueSim, falseSim, trueDelta*100, falseDelta*100)
		return true, conf, note
	}

	return false, 0, ""
}

// medianDurations returns the median of the provided durations.
func medianDurations(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), ds...)
	sortDurations(cp)
	mid := len(cp) / 2
	if len(cp)%2 == 0 {
		return (cp[mid-1] + cp[mid]) / 2
	}
	return cp[mid]
}
