//go:build darwin

package firewall

import (
	"fmt"
	"strconv"
	"strings"
)

const sfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

// osMajor returns the macOS major version (e.g. 26). It is a package var so
// tests can pin a version without execing sw_vers.
var osMajor = macOSMajor

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

	// macOS 15 (Sequoia) decoupled socketfilterfw's per-app store from actual
	// enforcement: --listapps no longer reflects real/GUI allow entries and
	// --add silently no-ops. We can neither verify nor set per-app status
	// programmatically, so report a low-confidence advisory (rendered as a
	// plain hint, never the "run firewall-allow" CTA) pointing at the GUI.
	if osMajor() >= 15 {
		st.Authorized = false
		st.Confidence = ConfidenceLow
		st.Detail = "enabled — can't auto-verify pmux on macOS 15+; if your phone can't connect, allow pmux in System Settings ▸ Network ▸ Firewall ▸ Options"
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
	// On macOS 15+ socketfilterfw --add no longer affects enforcement; the only
	// working path is the GUI. Signal that so the caller shows the steps instead
	// of (uselessly) elevating.
	if osMajor() >= 15 {
		return fmt.Errorf("%w:\n%s", ErrManualOnly, darwinManager{}.RemediationText(binPath))
	}
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
	if osMajor() >= 15 {
		return "macOS 15+ can't add firewall exceptions from the command line. Allow pmux manually:\n" +
			"    1. Open System Settings ▸ Network ▸ Firewall ▸ Options…\n" +
			"    2. Click + and add: " + binPath + "\n" +
			"    3. Set it to \"Allow incoming connections\""
	}
	q := shellQuote(binPath)
	return fmt.Sprintf("sudo %s --add %s && sudo %s --unblockapp %s", sfw, q, sfw, q)
}

// macOSMajor returns the running macOS major version (e.g. 26), or 0 if it
// can't be determined. Best-effort: callers treat 0 as "pre-15" (the legacy
// socketfilterfw path), which is the safe default for the rare parse failure.
func macOSMajor() int {
	out, err := execCommand("sw_vers", "-productVersion").CombinedOutput()
	if err != nil {
		return 0
	}
	major, _, _ := strings.Cut(strings.TrimSpace(string(out)), ".")
	n, _ := strconv.Atoi(major)
	return n
}

// listappsAuthorized parses `socketfilterfw --listapps` output and reports
// whether binPath is present and allowed. Entries look like:
//
//	12 : /path/to/binary
//	             (Allow incoming connections)
//
// Only meaningful on macOS < 15; on 15+ this store is decoupled from enforcement.
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
