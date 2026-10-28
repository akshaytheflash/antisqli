package cli

import "testing"

func TestHostMatches(t *testing.T) {
	allowed := []string{"example.com", "*.example.org", "10.0.0.0/8", "2001:db8::/32", " LOCALHOST "}

	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"EXAMPLE.com", true},
		{"example.org", true},
		{"api.example.org", true},
		{"deep.api.example.org", true},
		{"notexample.org", false},
		{"example.org.evil.test", false},
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"11.0.0.1", false},
		{"2001:db8::1", true},
		{"localhost", true},
		{"", false},
	}
	for _, tc := range cases {
		if got := hostMatches(tc.host, allowed); got != tc.want {
			t.Errorf("hostMatches(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestHostMatchesEmptyAllowlist(t *testing.T) {
	if hostMatches("example.com", nil) {
		t.Fatal("empty allowlist must not match")
	}
	if hostMatches("example.com", []string{"", "   "}) {
		t.Fatal("blank entries must not match")
	}
}

func TestHostMatchesMalformedCIDR(t *testing.T) {
	if hostMatches("10.0.0.1", []string{"10.0.0.0/99"}) {
		t.Fatal("malformed CIDR must not match")
	}
	if hostMatches("not-an-ip", []string{"10.0.0.0/8"}) {
		t.Fatal("non-IP host must not match a CIDR entry")
	}
}
