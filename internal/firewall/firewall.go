// Package firewall detects whether the host firewall is likely blocking
// inbound connections to the pmux agent binary, and (when run elevated)
// applies an allow rule. It mirrors the internal/service package's structure:
// build-tag-selected NewManager() plus an injectable execCommand for tests.
//
// Probing is read-only and never elevates. Mutation (Allow) is guarded to
// require elevation and is reached only via the explicit, user-invoked
// `pmux agent firewall-allow` command.
package firewall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Confidence expresses how much to trust a Status.Authorized value.
type Confidence int

const (
	ConfidenceUnknown Confidence = iota
	ConfidenceLow
	ConfidenceHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "low"
	case ConfidenceHigh:
		return "high"
	default:
		return "unknown"
	}
}

// Status is the result of probing the host firewall for a given binary path.
type Status struct {
	Supported       bool       // platform has a known firewall mechanism
	FirewallEnabled bool       // host firewall is on
	Authorized      bool       // our binary is allowed inbound (best-effort)
	Confidence      Confidence // trust level for Authorized
	Detail          string     // human-readable explanation
	Path            string     // resolved binary path that was probed
}

// Manager probes and (only when elevated) mutates the host firewall.
type Manager interface {
	// Probe is read-only, never elevates, and never returns a fatal error;
	// on uncertainty it returns Confidence Unknown.
	Probe(binPath string) Status
	// Allow applies an inbound allow rule for binPath. It MUST be run
	// elevated; implementations guard on this and return an error otherwise.
	Allow(binPath string) error
	// RemediationText returns the exact, copy-pasteable elevated command
	// for this OS, with the path safely quoted.
	RemediationText(binPath string) string
}

// NeedsAttention reports whether the firewall is likely blocking the agent.
// Package-level (not on Manager) because the logic is platform-independent.
func NeedsAttention(s Status) bool {
	return s.Supported && s.FirewallEnabled && !s.Authorized
}

// ExecutablePath returns the fully resolved path of the running executable
// (symlinks evaluated) — the path the OS firewall keys on. Call it at each
// site that needs the path; never cache it across processes (a path captured
// before an upgrade can go stale).
func ExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe, nil // best-effort: fall back to the unresolved path
	}
	return resolved, nil
}

// shellQuote wraps s in POSIX single quotes, escaping embedded single quotes,
// so it is safe to display in a copy-paste shell command with spaces/specials.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var errUnsupported = errors.New("automatic firewall configuration is not supported on this platform")

// unsupportedManager is returned on platforms without a known firewall mechanism.
type unsupportedManager struct{}

func (unsupportedManager) Probe(binPath string) Status {
	return Status{Supported: false, Confidence: ConfidenceUnknown, Path: binPath}
}
func (unsupportedManager) Allow(string) error { return errUnsupported }
func (unsupportedManager) RemediationText(string) string {
	return "Automatic firewall configuration is not supported on this platform."
}
