package detect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/akshaytheflash/antisqli/internal/model"
	"github.com/akshaytheflash/antisqli/internal/payload"
	"github.com/akshaytheflash/antisqli/internal/waf"
)

// checkTime performs time-based blind detection. Requests are serialized by
// the caller so latency measurements are not distorted by concurrent traffic.
func (e *Engine) checkTime(ctx context.Context, p model.Point, base *Baseline) []model.Finding {
	// A baseline that is already slow or extremely jittery makes timing
	// inference unreliable.
	if base.Median > 3*time.Second {
		e.debug("skipping time-based check for %s: baseline latency %s too high", p.Describe(), fmtDuration(base.Median))
		return nil
	}

	delay := e.opts.TimeDelay
	delayDur := time.Duration(delay) * time.Second
	// Require at least 55% of the injected delay to be observable.
	threshold := base.Median + time.Duration(float64(delayDur)*0.55)
	payloads := payload.TimePayloads(e.targetDBMS(), delay, e.opts.Level)

	for _, tp := range payloads {
		if ctx.Err() != nil || e.budgetExceeded() {
			return nil
		}

		probe, err := e.send(ctx, p, tp.Value)
		if err != nil {
			if errors.Is(err, ErrBudget) {
				return nil
			}
			continue
		}
		if probe.resp == nil || probe.resp.Err != nil {
			continue
		}
		if waf.Blocked(probe.resp) {
			e.blocked.Add(1)
			continue
		}
		if probe.resp.Duration < threshold {
			continue
		}

		e.debug("time-based candidate on %s with %s: %s (baseline %s)",
			p.Describe(), tp.Name, fmtDuration(probe.resp.Duration), fmtDuration(base.Median))

		// Confirm: collect additional samples and use the median to reject
		// one-off latency spikes.
		times := []time.Duration{probe.resp.Duration}
		for len(times) < e.opts.Samples {
			ex, err := e.send(ctx, p, tp.Value)
			if err != nil {
				break
			}
			if ex.resp == nil || ex.resp.Err != nil {
				continue
			}
			times = append(times, ex.resp.Duration)
		}
		if len(times) < 2 {
			continue
		}
		med := medianDurations(times)
		if med < threshold {
			continue
		}

		// Control request: the same payload with a zero delay must return at
		// baseline speed, proving the delay came from the injected expression.
		control := payload.ZeroDelay(tp.Value, delay)
		allAbove := true
		for _, d := range times {
			if d < threshold {
				allAbove = false
				break
			}
		}
		if control != "" {
			ctrl, err := e.send(ctx, p, control)
			if err != nil || ctrl.resp == nil || ctrl.resp.Err != nil {
				continue
			}
			if ctrl.resp.Duration >= threshold {
				e.debug("time-based candidate rejected: control request took %s", fmtDuration(ctrl.resp.Duration))
				continue
			}
		} else if !allAbove {
			// No control available: demand that every sample exceeds the
			// threshold.
			continue
		}

		ratio := float64(med-base.Median) / float64(delayDur)
		conf := clamp(0.72+ratio*0.30, 0.72, 0.98)
		if control != "" {
			conf = clamp(conf+0.02, 0.72, 0.99)
		}

		details := map[string]string{
			"delay_seconds": fmt.Sprintf("%d", delay),
			"baseline_ms":   fmt.Sprintf("%.0f", float64(base.Median)/float64(time.Millisecond)),
			"observed_ms":   fmt.Sprintf("%.0f", float64(med)/float64(time.Millisecond)),
			"payload":       tp.Name,
			"samples":       fmt.Sprintf("%d", len(times)),
		}
		evidence := fmt.Sprintf("response delayed to %s vs %s baseline (control returned normally)",
			fmtDuration(med), fmtDuration(base.Median))
		f := e.makeFinding(p, payload.Time, tp.DBMS, conf, tp.Value, evidence, details, probe)
		return []model.Finding{f}
	}
	return nil
}
