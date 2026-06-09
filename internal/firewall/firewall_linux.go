//go:build linux

package firewall

import (
	"fmt"
	"strings"
)

type linuxManager struct{}

// NewManager returns the Linux Manager. Detection is best-effort and
// remediation is advisory: per-binary inbound UDP rules are not cleanly
// expressible in ufw/firewalld, so we never mutate the firewall automatically.
func NewManager() Manager { return linuxManager{} }

func (linuxManager) Probe(binPath string) Status {
	// Confidence is always Low on Linux: most desktop hosts have no inbound
	// blocking firewall, and `ufw status` reports "inactive" to non-root even
	// when active. We detect an active host firewall to inform the user.
	st := Status{Supported: true, Path: binPath, Confidence: ConfidenceLow, Authorized: true}

	if out, err := execCommand("ufw", "status").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "Status: active") {
			st.FirewallEnabled = true
			st.Authorized = false
			st.Detail = "ufw is active; inbound UDP to pmux may be blocked"
			return st
		}
	}
	if out, err := execCommand("firewall-cmd", "--state").CombinedOutput(); err == nil {
		if strings.Contains(string(out), "running") {
			st.FirewallEnabled = true
			st.Authorized = false
			st.Detail = "firewalld is running; inbound UDP to pmux may be blocked"
			return st
		}
	}
	st.Detail = "no active host firewall detected (or could not verify without root)"
	return st
}

func (linuxManager) Allow(binPath string) error {
	return fmt.Errorf("automatic firewall rules are not supported on Linux; %s",
		linuxManager{}.RemediationText(binPath))
}

func (linuxManager) RemediationText(binPath string) string {
	return "If ufw/firewalld is active and blocking inbound UDP, the TURN relay path will not help — " +
		"allow inbound UDP for pmux, e.g. `sudo ufw allow proto udp from any to any` (scope to your LAN as appropriate), " +
		"or add a firewalld rule. See the pmux docs for guidance."
}
