//go:build darwin

package firewall

import (
	"fmt"
	"strings"
)

const sfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

type darwinManager struct{}

// NewManager returns the macOS (Application Firewall) Manager.
func NewManager() Manager { return darwinManager{} }

func (darwinManager) Probe(binPath string) Status {
	st := Status{Supported: true, Path: binPath, Confidence: ConfidenceHigh}

	out, err := execCommand(sfw, "--getglobalstate").CombinedOutput()
	if err != nil {
		return Status{Supported: true, Path: binPath, Confidence: ConfidenceUnknown,
			Detail: "could not read firewall state"}
	}
	st.FirewallEnabled = strings.Contains(string(out), "enabled")
	if !st.FirewallEnabled {
		st.Authorized = true
		st.Detail = "firewall disabled"
		return st
	}

	if ba, err := execCommand(sfw, "--getblockall").CombinedOutput(); err == nil &&
		strings.Contains(string(ba), "set to enabled") {
		st.Authorized = false
		st.Detail = "block-all mode active; all inbound connections blocked"
		return st
	}

	listOut, err := execCommand(sfw, "--listapps").CombinedOutput()
	if err != nil {
		st.Confidence = ConfidenceUnknown
		st.Detail = "could not list firewall apps"
		return st
	}
	allowed, found := listappsAuthorized(string(listOut), binPath)
	switch {
	case !found:
		st.Authorized = false
		st.Detail = "pmux is not in the firewall allow-list"
	case !allowed:
		st.Authorized = false
		st.Detail = "pmux is set to block incoming connections"
	default:
		st.Authorized = true
		st.Detail = "pmux is allowed"
	}
	return st
}

func (darwinManager) Allow(binPath string) error {
	if !isElevated() {
		return fmt.Errorf("firewall changes require root; run: pmux agent firewall-allow")
	}
	if out, err := execCommand(sfw, "--add", binPath).CombinedOutput(); err != nil {
		return fmt.Errorf("socketfilterfw --add: %s: %w", strings.TrimSpace(string(out)), err)
	}
	if out, err := execCommand(sfw, "--unblockapp", binPath).CombinedOutput(); err != nil {
		return fmt.Errorf("socketfilterfw --unblockapp: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func (darwinManager) RemediationText(binPath string) string {
	q := shellQuote(binPath)
	return fmt.Sprintf("sudo %s --add %s && sudo %s --unblockapp %s", sfw, q, sfw, q)
}

// listappsAuthorized parses `socketfilterfw --listapps` output and reports
// whether binPath is present and allowed. Entries look like:
//
//	12 : /path/to/binary
//	             (Allow incoming connections)
func listappsAuthorized(out, binPath string) (allowed, found bool) {
	lines := strings.Split(out, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		idx := strings.Index(line, " : ")
		if idx == -1 {
			continue
		}
		if strings.TrimSpace(line[idx+3:]) != binPath {
			continue
		}
		found = true
		for j := i + 1; j < len(lines) && j <= i+2; j++ {
			s := lines[j]
			if strings.Contains(s, "Allow") {
				return true, true
			}
			if strings.Contains(s, "Block") {
				return false, true
			}
		}
		return false, true
	}
	return false, false
}
