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
		{"unsupported", Status{Supported: false, FirewallEnabled: true, Authorized: false}, false},
		{"disabled", Status{Supported: true, FirewallEnabled: false, Authorized: false}, false},
		{"authorized", Status{Supported: true, FirewallEnabled: true, Authorized: true}, false},
		{"blocked", Status{Supported: true, FirewallEnabled: true, Authorized: false}, true},
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
	cases := map[string]string{
		"/opt/pmux":       "'/opt/pmux'",
		"/Users/a b/pmux": "'/Users/a b/pmux'",
		"/x/o'brien/pmux": `'/x/o'\''brien/pmux'`,
	}
	for in, want := range cases {
		if got := shellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}
