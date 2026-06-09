//go:build windows

package firewall

import (
	"fmt"
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

func (windowsManager) Allow(binPath string) error {
	if !isElevated() {
		return fmt.Errorf("firewall changes require Administrator; run: pmux agent firewall-allow")
	}
	// Remove any existing same-name rule first (idempotent; ignore "no rules match").
	_ = execCommand("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+fwRuleName).Run()
	out, err := execCommand("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+fwRuleName,
		"dir=in",
		"action=allow",
		"program="+binPath,
		"enable=yes",
		"profile=private,domain").CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh advfirewall firewall add rule: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (windowsManager) RemediationText(binPath string) string {
	return fmt.Sprintf(
		`netsh advfirewall firewall add rule name="%s" dir=in action=allow program="%s" enable=yes profile=private,domain (run in an elevated Command Prompt)`,
		fwRuleName, binPath)
}
