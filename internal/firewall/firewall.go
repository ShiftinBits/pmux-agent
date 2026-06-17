// Package firewall detects whether the host firewall is likely blocking
// inbound connections to the pmux agent binary. It is detection-only: it uses
// a build-tag-selected NewManager() plus an injectable execCommand for tests
// and never mutates the firewall.
//
// When a probe suggests the firewall may be blocking, callers surface the
// Warning message. There is deliberately no automatic fix: modern macOS can't
// add an exception from the CLI, and the mobile app falls back to a TURN relay
// automatically when a direct connection can't form.
package firewall

import (
	"fmt"
	"os"
	"path/filepath"
)

// Warning is the single user-facing message shown whenever the host firewall is
// suspected of blocking inbound connections to the agent.
const Warning = "Warning: Your firewall may be blocking pmux agent connectivity. Ensure pmux is allowed in your firewall to support direct peer-to-peer connections."

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
	Detail          string     // human-readable explanation (diagnostics/logs)
	Path            string     // resolved binary path that was probed
}

// Manager probes the host firewall. Detection-only; it never mutates the
// firewall.
type Manager interface {
	// Probe is read-only and never returns a fatal error; on uncertainty it
	// returns Confidence Unknown.
	Probe(binPath string) Status
}

// NeedsAttention reports whether the firewall is likely blocking the agent.
// Package-level (not on Manager) because the logic is platform-independent.
// A Status with Unknown confidence (e.g. a transient probe failure) does not
// trigger attention, to avoid false alarms.
func NeedsAttention(s Status) bool {
	return s.Supported && s.FirewallEnabled && !s.Authorized && s.Confidence != ConfidenceUnknown
}

// ExecutablePath returns the fully resolved path of the running executable
// (symlinks evaluated) — the path the OS firewall keys on. Call it at each
// site that needs the path; never cache it across processes (a path captured
// before an upgrade can go stale).
func ExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("firewall: resolve executable path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return exe, nil // best-effort: fall back to the unresolved path
	}
	return resolved, nil
}

// unsupportedManager is returned on platforms without a known firewall mechanism.
type unsupportedManager struct{}

func (unsupportedManager) Probe(binPath string) Status {
	return Status{Supported: false, Confidence: ConfidenceUnknown, Path: binPath}
}
