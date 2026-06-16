//go:build windows

package firewall

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// winStub maps the firewall-profile query and the rule query to behaviors,
// disambiguated by a marker substring in the powershell args.
func winStub(profileBehavior, ruleBehavior string) func(string, ...string) *exec.Cmd {
	return func(name string, args ...string) *exec.Cmd {
		behavior := profileBehavior
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "NetFirewallRule") || strings.Contains(joined, "DisplayName") {
			behavior = ruleBehavior
		}
		cs := append([]string{"-test.run=TestHelperProcess", "--", name}, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1", "GO_HELPER_BEHAVIOR="+behavior)
		return cmd
	}
}

func TestWindowsProbe(t *testing.T) {
	const p = `C:\Program Files\pmux\pmux.exe`
	cases := []struct {
		name           string
		profile, rule  string
		wantEnabled    bool
		wantAuthorized bool
		wantConf       Confidence
	}{
		{"disabled", "win_profile_off", "win_rule_absent", false, true, ConfidenceHigh},
		{"absent", "win_profile_on", "win_rule_absent", true, false, ConfidenceHigh},
		{"present", "win_profile_on", "win_rule_present", true, true, ConfidenceHigh},
		{"profile_error", "failure", "win_rule_absent", false, false, ConfidenceUnknown},
		{"rule_error", "win_profile_on", "failure", true, false, ConfidenceUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			execCommand = winStub(tc.profile, tc.rule)
			defer func() { execCommand = exec.Command }()
			st := windowsManager{}.Probe(p)
			if st.FirewallEnabled != tc.wantEnabled {
				t.Errorf("FirewallEnabled=%v want %v", st.FirewallEnabled, tc.wantEnabled)
			}
			if st.Authorized != tc.wantAuthorized {
				t.Errorf("Authorized=%v want %v (%s)", st.Authorized, tc.wantAuthorized, st.Detail)
			}
			if st.Confidence != tc.wantConf {
				t.Errorf("Confidence=%v want %v", st.Confidence, tc.wantConf)
			}
		})
	}
}

