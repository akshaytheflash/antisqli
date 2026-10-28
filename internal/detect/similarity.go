package detect

import (
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"time"
	"unicode"

	"github.com/akshaytheflash/antisqli/internal/model"
)

// shingleSize is the token n-gram size used for similarity scoring.
const shingleSize = 3

// maxTokens bounds tokenization work on very large documents.
const maxTokens = 20000

// Baseline captures the normal behavior of an injection point.
type Baseline struct {
	Resp     *model.Response
	Samples  []*model.Response
	Status   int
	Length   int
	Shingles map[uint64]struct{}
	Sigs     map[string]bool
	Volatile map[string]bool
	Median   time.Duration
	MAD      time.Duration
	Title    string
	Body     string
}

// newBaseline builds a baseline from at least one response sample.
func newBaseline(samples []*model.Response) *Baseline {
	b := &Baseline{Samples: samples}
	if len(samples) == 0 {
		return b
	}
	b.Resp = samples[0]
	b.Status = samples[0].Status
	b.Length = len(samples[0].Body)
	b.Body = samples[0].Text()
	b.Title = extractTitle(b.Body)
	b.Volatile = learnVolatile(samples)
	b.Shingles = shingles(b.Body, b.Volatile)
	b.Sigs = signatureSet(b.Body)
	b.Median, b.MAD = medianDuration(samples)
	return b
}

// medianDuration returns the median and median absolute deviation of the
// sample durations.
func medianDuration(samples []*model.Response) (time.Duration, time.Duration) {
	if len(samples) == 0 {
		return 0, 0
	}
	ds := make([]time.Duration, 0, len(samples))
	for _, s := range samples {
		if s != nil && s.Err == nil {
			ds = append(ds, s.Duration)
		}
	}
	if len(ds) == 0 {
		return 0, 0
	}
	sortDurations(ds)
	med := ds[len(ds)/2]
	if len(ds)%2 == 0 {
		med = (ds[len(ds)/2-1] + ds[len(ds)/2]) / 2
	}
	dev := make([]time.Duration, len(ds))
	for i, d := range ds {
		dev[i] = absDuration(d - med)
	}
	sortDurations(dev)
	mad := dev[len(dev)/2]
	return med, mad
}

func sortDurations(d []time.Duration) {
	for i := 1; i < len(d); i++ {
		for j := i; j > 0 && d[j] < d[j-1]; j-- {
			d[j], d[j-1] = d[j-1], d[j]
		}
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// learnVolatile identifies tokens that change between otherwise identical
// baseline requests (CSRF tokens, timestamps, cache busters).
func learnVolatile(samples []*model.Response) map[string]bool {
	volatile := map[string]bool{}
	if len(samples) < 2 {
		return volatile
	}
	counts := map[string]int{}
	for _, s := range samples {
		if s == nil {
			continue
		}
		seen := map[string]bool{}
		for _, tok := range tokenize(s.Text()) {
			if seen[tok] {
				continue
			}
			seen[tok] = true
			counts[tok]++
		}
	}
	for tok, n := range counts {
		if n < len(samples) {
			volatile[tok] = true
		}
	}
	return volatile
}

// tokenize splits text into lowercase alphanumeric tokens, applying
// volatility heuristics for values that look like nonces.
func tokenize(s string) []string {
	if len(s) > 2<<20 {
		s = s[:2<<20]
	}
	tokens := make([]string, 0, 1024)
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		tok := strings.ToLower(b.String())
		b.Reset()
		if looksVolatile(tok) {
			return
		}
		tokens = append(tokens, tok)
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if b.Len() < 128 {
				b.WriteRune(r)
			}
			continue
		}
		flush()
		if len(tokens) >= maxTokens {
			return tokens
		}
	}
	flush()
	if len(tokens) > maxTokens {
		tokens = tokens[:maxTokens]
	}
	return tokens
}

func looksVolatile(tok string) bool {
	n := len(tok)
	if n < 12 {
		return false
	}
	isHex, allDigits, hasUpper, hasLower := true, true, false, false
	for _, c := range tok {
		switch {
		case c >= '0' && c <= '9':
			// digits keep isHex and allDigits true
		case c >= 'a' && c <= 'f':
			allDigits = false
			hasLower = true
		case c >= 'A' && c <= 'F':
			allDigits = false
			hasUpper = true
		default:
			isHex = false
			allDigits = false
			if c >= 'a' && c <= 'z' {
				hasLower = true
			}
			if c >= 'A' && c <= 'Z' {
				hasUpper = true
			}
		}
	}
	if n >= 16 && isHex {
		return true
	}
	if n >= 24 && hasUpper && hasLower {
		return true
	}
	if n >= 8 && allDigits {
		return true
	}
	return false
}

// shingles builds a set of hashed token trigrams.
func shingles(text string, volatile map[string]bool) map[uint64]struct{} {
	tokens := tokenize(text)
	if volatile != nil {
		filtered := tokens[:0]
		for _, t := range tokens {
			if !volatile[t] {
				filtered = append(filtered, t)
			}
		}
		tokens = filtered
	}
	set := make(map[uint64]struct{}, len(tokens))
	if len(tokens) < shingleSize {
		if len(tokens) > 0 {
			set[hashTokens(tokens)] = struct{}{}
		}
		return set
	}
	for i := 0; i+shingleSize <= len(tokens); i++ {
		set[hashTokens(tokens[i:i+shingleSize])] = struct{}{}
	}
	return set
}

func hashTokens(tokens []string) uint64 {
	h := fnv.New64a()
	for _, t := range tokens {
		_, _ = h.Write([]byte(t))
		_, _ = h.Write([]byte{0})
	}
	return h.Sum64()
}

// similarity compares a response against the baseline body using Jaccard
// similarity over shingles. Volatile tokens are ignored.
func similarity(base *Baseline, resp *model.Response) float64 {
	if base == nil || resp == nil {
		return 0
	}
	if len(base.Shingles) == 0 {
		return lengthSimilarity(base.Length, len(resp.Body))
	}
	set := shingles(resp.Text(), base.Volatile)
	if len(set) == 0 {
		return 0
	}
	inter := 0
	for h := range set {
		if _, ok := base.Shingles[h]; ok {
			inter++
		}
	}
	union := len(set) + len(base.Shingles) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

// lengthSimilarity returns a 0..1 score based on body length difference.
func lengthSimilarity(a, b int) float64 {
	if a == 0 && b == 0 {
		return 1
	}
	max := a
	if b > max {
		max = b
	}
	if max == 0 {
		return 1
	}
	return 1 - float64(absInt(a-b))/float64(max)
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// relativeLengthDelta returns |a-b| / max(a,b).
func relativeLengthDelta(a, b int) float64 {
	max := a
	if b > max {
		max = b
	}
	if max == 0 {
		return 0
	}
	return float64(absInt(a-b)) / float64(max)
}

// extractTitle pulls the contents of the first <title> tag.
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start < 0 {
		return ""
	}
	start = strings.IndexByte(lower[start:], '>')
	if start < 0 {
		return ""
	}
	lower = lower[start:]
	end := strings.Index(lower, "</title>")
	if end < 0 {
		return ""
	}
	title := lower[1:end]
	if len(title) > 200 {
		title = title[:200]
	}
	return strings.TrimSpace(title)
}

// similarityGrade renders a similarity score for debug output.
func similarityGrade(v float64) string {
	switch {
	case v >= 0.95:
		return "identical"
	case v >= 0.85:
		return "very-similar"
	case v >= 0.65:
		return "similar"
	case v >= 0.35:
		return "different"
	default:
		return "very-different"
	}
}

// round2 rounds to two decimals for stable reporting.
func round2(v float64) float64 { return math.Round(v*100) / 100 }

func fmtDuration(d time.Duration) string {
	return fmt.Sprintf("%.0fms", float64(d)/float64(time.Millisecond))
}
