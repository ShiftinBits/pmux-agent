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
	_ = execCommand("powershell", "-NonInteractive", "-Command",
		"Remove-NetFirewallRule", "-DisplayName", fwRuleName, "-ErrorAction", "SilentlyContinue").Run()
	out, err := execCommand("powershell", "-NonInteractive", "-Command",
		"New-NetFirewallRule",
		"-DisplayName", fwRuleName,
		"-Direction", "Inbound",
		"-Program", binPath,
		"-Action", "Allow",
		"-Profile", "Private,Domain").CombinedOutput()
	if err != nil {
		return fmt.Errorf("New-NetFirewallRule: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (windowsManager) RemediationText(binPath string) string {
	return fmt.Sprintf(
		`New-NetFirewallRule -DisplayName '%s' -Direction Inbound -Program '%s' -Action Allow -Profile Private,Domain  (run in an elevated PowerShell)`,
		fwRuleName, strings.ReplaceAll(binPath, "'", "''"))
}
