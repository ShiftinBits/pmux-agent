//go:build linux

package firewall

import (
	"os/exec"
	"testing"
)

func TestLinuxProbe(t *testing.T) {
	cases := []struct {
		name        string
		ufw, fwd    string
		wantEnabled bool
		wantConf    Confidence
	}{
		{"ufw_active", "linux_ufw_active", "linux_fwd_absent", true, ConfidenceLow},
		{"ufw_inactive", "linux_ufw_inactive", "linux_fwd_absent", false, ConfidenceLow},
		{"none", "linux_ufw_missing", "linux_fwd_absent", false, ConfidenceLow},
		{"firewalld", "linux_ufw_inactive", "linux_fwd_running", true, ConfidenceLow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			execCommand = fakeByArg(map[string]string{
				"ufw":          tc.ufw,
				"firewall-cmd": tc.fwd,
			})
			defer func() { execCommand = exec.Command }()
			st := linuxManager{}.Probe("/usr/bin/pmux")
			if st.FirewallEnabled != tc.wantEnabled {
				t.Errorf("FirewallEnabled=%v want %v", st.FirewallEnabled, tc.wantEnabled)
			}
			if st.Confidence != tc.wantConf {
				t.Errorf("Confidence=%v want %v", st.Confidence, tc.wantConf)
			}
		})
	}
}

