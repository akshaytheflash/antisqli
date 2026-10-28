package payload

import (
	"strings"
	"testing"
)

func TestApplyTampers(t *testing.T) {
	tests := []struct {
		name  string
		value string
		chain []string
		want  string
	}{
		{"space2comment", "' AND 1=1", []string{"space2comment"}, "'/**/AND/**/1=1"},
		{"charencode", "a'b", []string{"charencode"}, "a%27b"},
		{"apostrophe", "a'b", []string{"apostrophe"}, "a%27b"},
		{"equaltolike", "1=1", []string{"equaltolike"}, "1 LIKE 1"},
		{"chain", "a b", []string{"space2plus", "randomcase"}, "A+B"},
		{"no tampers", "' OR 1=1", nil, "' OR 1=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Apply(tt.value, tt.chain)
			if err != nil {
				t.Fatalf("Apply: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApplyUnknownTamper(t *testing.T) {
	if _, err := Apply("x", []string{"nope"}); err == nil {
		t.Fatal("expected error for unknown tamper")
	}
}

func TestZeroDelay(t *testing.T) {
	cases := map[string]string{
		"' AND SLEEP(5)-- -":                         "' AND SLEEP(0)-- -",
		"' AND 1=(SELECT 1 FROM PG_SLEEP(5))":        "' AND 1=(SELECT 1 FROM PG_SLEEP(0))",
		"; WAITFOR DELAY '0:0:5'":                    "; WAITFOR DELAY '0:0:0'",
		"' AND 1=dbms_pipe.receive_message(('a'),5)": "' AND 1=dbms_pipe.receive_message(('a'),0)",
	}
	for in, want := range cases {
		if got := ZeroDelay(in, 5); got != want {
			t.Errorf("ZeroDelay(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ZeroDelay("' AND randomblob(100)", 5); got != "" {
		t.Errorf("expected empty control for non-time payload, got %q", got)
	}
}

func TestBooleanPairsAreUniqueAndPaired(t *testing.T) {
	pairs := BooleanPairs(2, 2)
	if len(pairs) == 0 {
		t.Fatal("no pairs generated")
	}
	seen := map[string]bool{}
	for _, p := range pairs {
		if p.True == p.False {
			t.Fatalf("true and false payloads are equal: %q", p.True)
		}
		key := p.True + "|" + p.False
		if seen[key] {
			t.Fatalf("duplicate pair %q", key)
		}
		seen[key] = true
	}
}

func TestBooleanPairsLevelGrowth(t *testing.T) {
	l1 := len(BooleanPairs(1, 1))
	l2 := len(BooleanPairs(2, 1))
	l3 := len(BooleanPairs(3, 2))
	if !(l1 < l2 && l2 < l3) {
		t.Fatalf("expected increasing coverage, got %d, %d, %d", l1, l2, l3)
	}
}

func TestTimePayloads(t *testing.T) {
	for _, dbms := range []string{"mysql", "postgres", "mssql"} {
		ps := TimePayloads(dbms, 7, 1)
		if len(ps) == 0 {
			t.Fatalf("no time payloads for %s", dbms)
		}
		for _, p := range ps {
			if !strings.Contains(p.Value, "7") {
				t.Fatalf("%s payload missing delay: %q", dbms, p.Value)
			}
			if ZeroDelay(p.Value, 7) == "" {
				t.Fatalf("payload has no zero-delay control: %q", p.Value)
			}
		}
	}
}

func TestUnionSelectColumnCount(t *testing.T) {
	got := UnionSelect("'", 3, "mark", "mysql")
	want := "' UNION SELECT 'mark',NULL,NULL-- -"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if cols := strings.Count(got, "NULL"); cols != 2 {
		t.Fatalf("expected 2 NULL columns, got %d", cols)
	}
}

func TestPriority(t *testing.T) {
	if Priority("id") <= Priority("unlikely") {
		t.Fatal("expected id to rank above unknown parameter")
	}
	if Priority("product_id") <= Priority("unlikely") {
		t.Fatal("expected substring match to rank above unknown parameter")
	}
}

func TestTamperDocsCoverRegistry(t *testing.T) {
	docs := TamperDocs()
	if len(docs) != len(TamperNames()) {
		t.Fatalf("docs=%d names=%d", len(docs), len(TamperNames()))
	}
	for _, d := range docs {
		if d.Description == "" {
			t.Errorf("missing description for %s", d.Name)
		}
	}
}
