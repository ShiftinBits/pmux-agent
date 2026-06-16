//go:build windows

package firewall

import (
	"strings"
)

const fwRuleName = "pmux agent"

type windowsManager struct{}

// NewManager returns the Windows Defender Firewall Manager.
func NewManager() Manager { return windowsManager{} }

func (windowsManager) Probe(binPath string) Status {
	st := Status{Supported: true, Path: binPath, Confidence: ConfidenceHigh}

	out, err := execCommand("powershell", "-NonInteractive", "-Command",
		"(Get-NetFirewallProfile | Where-Object Enabled -eq 'True' | Measure-Object).Count -gt 0").CombinedOutput()
	if err != nil {
		return Status{Supported: true, Path: binPath, Confidence: ConfidenceUnknown,
			Detail: "could not read firewall state"}
	}
	st.FirewallEnabled = strings.Contains(strings.ToLower(string(out)), "true")
	if !st.FirewallEnabled {
		st.Authorized = true
		st.Detail = "firewall disabled on all profiles"
		return st
	}

	ruleOut, err := execCommand("powershell", "-NonInteractive", "-Command",
		"(Get-NetFirewallRule -DisplayName '"+fwRuleName+"' -ErrorAction SilentlyContinue).DisplayName").CombinedOutput()
	if err != nil {
		st.Confidence = ConfidenceUnknown
		st.Detail = "could not query firewall rules"
		return st
	}
	if strings.Contains(string(ruleOut), fwRuleName) {
		st.Authorized = true
		st.Detail = "inbound allow rule present"
	} else {
		st.Authorized = false
		st.Detail = "no inbound allow rule for pmux"
	}
	return st
}
