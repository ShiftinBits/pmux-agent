//go:build darwin

package firewall

import (
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

func TestDarwinProbe(t *testing.T) {
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

func TestDarwinRemediationText(t *testing.T) {
	got := darwinManager{}.RemediationText("/Users/a b/pmux")
	if !strings.Contains(got, "--unblockapp '/Users/a b/pmux'") {
		t.Errorf("RemediationText missing quoted --unblockapp: %q", got)
	}
	if strings.Contains(got, "--unblock ") {
		t.Errorf("RemediationText uses wrong flag --unblock: %q", got)
	}
}

func TestDarwinAllowRequiresElevation(t *testing.T) {
	if isElevated() {
		t.Skip("test runner is elevated; skipping non-elevated guard check")
	}
	if err := (darwinManager{}).Allow("/opt/pmux"); err == nil {
		t.Fatal("expected Allow to error when not elevated")
	}
}
