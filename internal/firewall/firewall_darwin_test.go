//go:build darwin

package firewall

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// stubMac maps socketfilterfw's first flag to a behavior for darwin tests.
func stubMac(global, blockall, listapps string) func(string, ...string) *exec.Cmd {
	return fakeByArg(map[string]string{
		sfw + " --getglobalstate": global,
		sfw + " --getblockall":    blockall,
		sfw + " --listapps":       listapps,
	})
}

// pinOSMajor sets osMajor to a fixed version for the duration of a test.
func pinOSMajor(t *testing.T, v int) {
	t.Helper()
	prev := osMajor
	osMajor = func() int { return v }
	t.Cleanup(func() { osMajor = prev })
}

func TestListappsAuthorized(t *testing.T) {
	out := "Total number of apps = 3 \n" +
		"1 : /opt/homebrew/Caskroom/pmux/0.3.1/pmux \n" +
		"             (Allow incoming connections) \n" +
		"2 : /opt/homebrew/Caskroom/pmux/0.3.2/pmux \n" +
		"             (Block incoming connections) \n"
	cases := []struct {
		path        string
		wantAllowed bool
		wantFound   bool
	}{
		{"/opt/homebrew/Caskroom/pmux/0.3.1/pmux", true, true},
		{"/opt/homebrew/Caskroom/pmux/0.3.2/pmux", false, true},
		{"/opt/homebrew/Caskroom/pmux/9.9.9/pmux", false, false},
	}
	for _, tc := range cases {
		allowed, found := listappsAuthorized(out, tc.path)
		if allowed != tc.wantAllowed || found != tc.wantFound {
			t.Errorf("listappsAuthorized(%q) = (%v,%v), want (%v,%v)",
				tc.path, allowed, found, tc.wantAllowed, tc.wantFound)
		}
	}
}

// TestDarwinProbe covers the legacy (macOS < 15) socketfilterfw path, where the
// per-app allow-list still drives enforcement.
func TestDarwinProbe(t *testing.T) {
	pinOSMajor(t, 14)
	const p = "/opt/homebrew/Caskroom/pmux/0.3.2/pmux"
	cases := []struct {
		name           string
		global, ba, la string
		wantEnabled    bool
		wantAuthorized bool
		wantConf       Confidence
	}{
		{"disabled", "mac_global_off", "mac_blockall_off", "mac_listapps_absent", false, true, ConfidenceHigh},
		{"blockall", "mac_global_on", "mac_blockall_on", "mac_listapps_allowed", true, false, ConfidenceHigh},
		{"absent", "mac_global_on", "mac_blockall_off", "mac_listapps_absent", true, false, ConfidenceHigh},
		{"allowed", "mac_global_on", "mac_blockall_off", "mac_listapps_allowed", true, true, ConfidenceHigh},
		{"blocked", "mac_global_on", "mac_blockall_off", "mac_listapps_blocked", true, false, ConfidenceHigh},
		{"globalstate_error", "failure", "mac_blockall_off", "mac_listapps_absent", false, false, ConfidenceUnknown},
		{"listapps_error", "mac_global_on", "mac_blockall_off", "failure", true, false, ConfidenceUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			execCommand = stubMac(tc.global, tc.ba, tc.la)
			defer func() { execCommand = exec.Command }()
			st := darwinManager{}.Probe(p)
			if !st.Supported {
				t.Fatal("expected Supported=true")
			}
			if st.FirewallEnabled != tc.wantEnabled {
				t.Errorf("FirewallEnabled = %v, want %v", st.FirewallEnabled, tc.wantEnabled)
			}
			if st.Authorized != tc.wantAuthorized {
				t.Errorf("Authorized = %v, want %v (detail=%q)", st.Authorized, tc.wantAuthorized, st.Detail)
			}
			if st.Confidence != tc.wantConf {
				t.Errorf("Confidence = %v, want %v", st.Confidence, tc.wantConf)
			}
		})
	}
}

// TestDarwinProbeSequoia covers macOS 15+, where socketfilterfw's per-app store
// is decoupled from enforcement: Probe must not consult --listapps and instead
// returns a low-confidence advisory (so callers show a hint, never NeedsAttention
// with the firewall-allow CTA that can't work here).
func TestDarwinProbeSequoia(t *testing.T) {
	pinOSMajor(t, 26)
	const p = "/opt/homebrew/Caskroom/pmux/0.4.0/pmux"

	// Firewall on, not block-all → advisory. --listapps must never be consulted;
	// stub it to fail so the test breaks if Probe falls through to it.
	execCommand = fakeByArg(map[string]string{
		sfw + " --getglobalstate": "mac_global_on",
		sfw + " --getblockall":    "mac_blockall_off",
		sfw + " --listapps":       "failure",
	})
	defer func() { execCommand = exec.Command }()

	st := darwinManager{}.Probe(p)
	if st.Authorized {
		t.Errorf("Authorized = true, want false on macOS 15+ (can't verify)")
	}
	if st.Confidence != ConfidenceLow {
		t.Errorf("Confidence = %v, want Low", st.Confidence)
	}
	if !strings.Contains(st.Detail, "System Settings") {
		t.Errorf("Detail should point at System Settings, got %q", st.Detail)
	}
	// Low confidence + not authorized → advisory, but must still NeedAttention so
	// the hint surfaces.
	if !NeedsAttention(st) {
		t.Error("expected NeedsAttention=true for the macOS 15+ advisory")
	}

	// Firewall disabled short-circuits to authorized regardless of version.
	execCommand = fakeByArg(map[string]string{sfw + " --getglobalstate": "mac_global_off"})
	if st := (darwinManager{}).Probe(p); !st.Authorized {
		t.Error("expected Authorized=true when firewall disabled")
	}
}

func TestDarwinRemediationText(t *testing.T) {
	t.Run("legacy", func(t *testing.T) {
		pinOSMajor(t, 14)
		got := darwinManager{}.RemediationText("/Users/a b/pmux")
		if !strings.Contains(got, "--unblockapp '/Users/a b/pmux'") {
			t.Errorf("RemediationText missing quoted --unblockapp: %q", got)
		}
		if strings.Contains(got, "--unblock ") {
			t.Errorf("RemediationText uses wrong flag --unblock: %q", got)
		}
	})
	t.Run("sequoia", func(t *testing.T) {
		pinOSMajor(t, 26)
		got := darwinManager{}.RemediationText("/opt/homebrew/Caskroom/pmux/0.4.0/pmux")
		if !strings.Contains(got, "System Settings") || !strings.Contains(got, "0.4.0/pmux") {
			t.Errorf("RemediationText should give GUI steps with the path, got %q", got)
		}
		if strings.Contains(got, "socketfilterfw") {
			t.Errorf("macOS 15+ RemediationText must not suggest socketfilterfw: %q", got)
		}
	})
}

func TestDarwinAllowSequoiaManualOnly(t *testing.T) {
	pinOSMajor(t, 26)
	err := darwinManager{}.Allow("/opt/homebrew/Caskroom/pmux/0.4.0/pmux")
	if !errors.Is(err, ErrManualOnly) {
		t.Fatalf("Allow on macOS 15+ should return ErrManualOnly, got %v", err)
	}
}

func TestDarwinAllowRequiresElevation(t *testing.T) {
	pinOSMajor(t, 14) // exercise the legacy elevation guard, not the 15+ path
	if isElevated() {
		t.Skip("test runner is elevated; skipping non-elevated guard check")
	}
	if err := (darwinManager{}).Allow("/opt/pmux"); err == nil {
		t.Fatal("expected Allow to error when not elevated")
	}
}
