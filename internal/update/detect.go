package update

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// InstallMethod represents how pmux was installed.
type InstallMethod string

const (
	MethodDev      InstallMethod = "dev"
	MethodSnap     InstallMethod = "snap"
	MethodDeb      InstallMethod = "deb"
	MethodRPM      InstallMethod = "rpm"
	MethodHomebrew InstallMethod = "homebrew"
	MethodGitHub   InstallMethod = "github"
)

// commandTimeout is the deadline for subprocess-based detection checks.
const commandTimeout = 2 * time.Second

// String returns a human-readable label for the install method.
func (m InstallMethod) String() string {
	switch m {
	case MethodDev:
		return "development build"
	case MethodSnap:
		return "Snap Store"
	case MethodDeb:
		return "Debian package (dpkg)"
	case MethodRPM:
		return "RPM package"
	case MethodHomebrew:
		return "Homebrew"
	case MethodGitHub:
		return "GitHub Releases (direct binary)"
	default:
		return string(m)
	}
}

// HasUpdatePath reports whether this install method has a known update path
// (either automated or guided with printed instructions).
func (m InstallMethod) HasUpdatePath() bool {
	switch m {
	case MethodHomebrew, MethodSnap, MethodDeb, MethodRPM, MethodGitHub:
		return true
	default:
		return false
	}
}

// executablePath is a variable for testing.
var executablePath = os.Executable

// Detect determines how pmux was installed using runtime heuristics.
// buildMethod is the value of main.installMethod set via ldflags
// ("dev" for local builds, empty for release builds).
func Detect(buildMethod string) InstallMethod {
	if buildMethod == "dev" {
		return MethodDev
	}

	// Check binary path for snap and homebrew indicators.
	exePath, err := executablePath()
	if err == nil {
		resolved, err := filepath.EvalSymlinks(exePath)
		if err == nil {
			exePath = resolved
		}

		if strings.Contains(exePath, "/snap/") {
			return MethodSnap
		}
		if strings.Contains(exePath, "/Cellar/") || strings.Contains(exePath, "/opt/homebrew/") {
			return MethodHomebrew
		}
	}

	// Check package managers with subprocess calls (with timeouts).
	if commandSucceeds("dpkg", "-s", "pmux") {
		return MethodDeb
	}
	if commandSucceeds("rpm", "-q", "pmux") {
		return MethodRPM
	}

	return MethodGitHub
}

// commandSucceeds runs a command with a timeout and returns true if it exits 0.
func commandSucceeds(name string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}
