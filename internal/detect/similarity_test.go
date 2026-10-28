package detect

import (
	"strings"
	"testing"
	"time"

	"github.com/akshaytheflash/antisqli/internal/model"
)

func resp(body string, dur time.Duration) *model.Response {
	return &model.Response{Status: 200, Body: []byte(body), Duration: dur}
}

func TestTokenize(t *testing.T) {
	tokens := tokenize("Hello, world! 123")
	if len(tokens) != 3 {
		t.Fatalf("expected 3 tokens, got %v", tokens)
	}
	if tokens[0] != "hello" {
		t.Fatalf("expected lowercase token, got %q", tokens[0])
	}
}

func TestLearnVolatile(t *testing.T) {
	a := resp(`<input name="csrf" value="tokenAAA"><p>stable content here</p>`, 10*time.Millisecond)
	b := resp(`<input name="csrf" value="tokenBBB"><p>stable content here</p>`, 10*time.Millisecond)
	base := newBaseline([]*model.Response{a, b})
	if !base.Volatile["tokenaaa"] || !base.Volatile["tokenbbb"] {
		t.Fatalf("volatile tokens not learned: %v", base.Volatile)
	}
	if base.Volatile["stable"] {
		t.Fatal("stable token marked volatile")
	}
}

func TestSimilarityIdentical(t *testing.T) {
	body := strings.Repeat("alpha beta gamma delta epsilon ", 40)
	base := newBaseline([]*model.Response{resp(body, time.Millisecond)})
	got := similarity(base, resp(body, time.Millisecond))
	if got < 0.99 {
		t.Fatalf("identical bodies scored %.2f", got)
	}
}

func TestSimilarityDifferent(t *testing.T) {
	a := strings.Repeat("alpha beta gamma delta epsilon ", 40)
	b := strings.Repeat("one two three four five ", 40)
	base := newBaseline([]*model.Response{resp(a, time.Millisecond)})
	got := similarity(base, resp(b, time.Millisecond))
	if got > 0.2 {
		t.Fatalf("different bodies scored %.2f", got)
	}
}

func TestRelativeLengthDelta(t *testing.T) {
	if got := relativeLengthDelta(100, 100); got != 0 {
		t.Fatalf("expected 0, got %f", got)
	}
	if got := relativeLengthDelta(100, 50); got != 0.5 {
		t.Fatalf("expected 0.5, got %f", got)
	}
	if got := relativeLengthDelta(0, 0); got != 0 {
		t.Fatalf("expected 0, got %f", got)
	}
}

func TestMedianDuration(t *testing.T) {
	samples := []*model.Response{
		resp("a", 10*time.Millisecond),
		resp("b", 30*time.Millisecond),
		resp("c", 20*time.Millisecond),
	}
	med, mad := medianDuration(samples)
	if med != 20*time.Millisecond {
		t.Fatalf("median = %s", med)
	}
	if mad != 10*time.Millisecond {
		t.Fatalf("mad = %s", mad)
	}
}

func TestEvaluateBooleanNormal(t *testing.T) {
	baseBody := strings.Repeat("product row data ", 60)
	base := newBaseline([]*model.Response{
		resp(baseBody, time.Millisecond),
		resp(baseBody, time.Millisecond),
	})
	trueResp := resp(baseBody, time.Millisecond)
	falseResp := resp("no results", time.Millisecond)
	ok, conf, _ := evaluateBoolean(base, 1, trueResp, falseResp)
	if !ok {
		t.Fatal("expected boolean injection to be detected")
	}
	if conf < 0.6 {
		t.Fatalf("confidence too low: %f", conf)
	}
}

func TestEvaluateBooleanRejectsSimilar(t *testing.T) {
	body := strings.Repeat("product row data ", 60)
	base := newBaseline([]*model.Response{resp(body, time.Millisecond)})
	ok, _, _ := evaluateBoolean(base, 1, resp(body, time.Millisecond), resp(body, time.Millisecond))
	if ok {
		t.Fatal("identical responses must not be reported as injection")
	}
}
