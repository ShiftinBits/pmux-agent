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
	}{
		{"disabled", "win_profile_off", "win_rule_absent", false, true},
		{"absent", "win_profile_on", "win_rule_absent", true, false},
		{"present", "win_profile_on", "win_rule_present", true, true},
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
		})
	}
}

func TestWindowsRemediationText(t *testing.T) {
	got := windowsManager{}.RemediationText(`C:\Program Files\pmux\pmux.exe`)
	if !strings.Contains(got, "New-NetFirewallRule") || !strings.Contains(got, "Private,Domain") {
		t.Errorf("unexpected remediation text: %q", got)
	}
}
