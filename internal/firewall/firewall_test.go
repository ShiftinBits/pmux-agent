package firewall

import (
	"os"
	"testing"
)

func TestNeedsAttention(t *testing.T) {
	cases := []struct {
		name string
		s    Status
		want bool
	}{
		{"unsupported", Status{Supported: false, FirewallEnabled: true, Authorized: false, Confidence: ConfidenceHigh}, false},
		{"disabled", Status{Supported: true, FirewallEnabled: false, Authorized: false, Confidence: ConfidenceHigh}, false},
		{"authorized", Status{Supported: true, FirewallEnabled: true, Authorized: true, Confidence: ConfidenceHigh}, false},
		{"blocked", Status{Supported: true, FirewallEnabled: true, Authorized: false, Confidence: ConfidenceHigh}, true},
		{"blocked-but-unknown", Status{Supported: true, FirewallEnabled: true, Authorized: false, Confidence: ConfidenceUnknown}, false},
		{"blocked-low-confidence", Status{Supported: true, FirewallEnabled: true, Authorized: false, Confidence: ConfidenceLow}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NeedsAttention(tc.s); got != tc.want {
				t.Errorf("NeedsAttention(%+v) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

func TestExecutablePath(t *testing.T) {
	p, err := ExecutablePath()
	if err != nil {
		t.Fatalf("ExecutablePath() error: %v", err)
	}
	if p == "" {
		t.Fatal("ExecutablePath() returned empty path")
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("ExecutablePath() = %q, not stat-able: %v", p, err)
	}
}

func TestShellQuote(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/opt/pmux", "'/opt/pmux'"},
		{"/Users/a b/pmux", "'/Users/a b/pmux'"},
		{"/x/o'brien/pmux", `'/x/o'\''brien/pmux'`},
	}
	for _, tc := range cases {
		if got := shellQuote(tc.in); got != tc.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
