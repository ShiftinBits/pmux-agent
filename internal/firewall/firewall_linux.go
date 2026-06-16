//go:build linux

package firewall

import (
	"strings"
)

type linuxManager struct{}

// NewManager returns the Linux Manager. Detection is best-effort; we never
// mutate the firewall (per-binary inbound UDP rules aren't cleanly expressible
// in ufw/firewalld). When blocking is suspected, callers surface the Warning
// and the mobile app falls back to a TURN relay.
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
