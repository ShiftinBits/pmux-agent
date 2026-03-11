package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	launchdLabel     = "io.pmux.agent"
	launchdPlistFile = "io.pmux.agent.plist"
)

// launchdManager manages the agent as a macOS launchd service.
type launchdManager struct {
	pmuxPath  string
	configDir string
	plistDir  string // override for testing; empty means ~/Library/LaunchAgents
}

func newLaunchdManager(pmuxPath, configDir string) *launchdManager {
	return &launchdManager{pmuxPath: pmuxPath, configDir: configDir}
}

func (m *launchdManager) plistPath() string {
	dir := m.plistDir
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, "Library", "LaunchAgents")
	}
	return filepath.Join(dir, launchdPlistFile)
}

func (m *launchdManager) generatePlist() string {
	logPath := filepath.Join(m.configDir, "agent.log")
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>%s</string>
	<key>ProgramArguments</key>
	<array>
		<string>%s</string>
		<string>agent</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>StandardOutPath</key>
	<string>%s</string>
	<key>StandardErrorPath</key>
	<string>%s</string>
</dict>
</plist>
`, launchdLabel, m.pmuxPath, logPath, logPath)
}

func (m *launchdManager) writePlist() error {
	path := m.plistPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}
	return os.WriteFile(path, []byte(m.generatePlist()), 0644)
}

// checkNotRoot returns an error if the process is running as root.
// launchd user agents must be installed in the user's GUI domain (gui/<uid>),
// which doesn't exist for root. Running via sudo is the most common cause.
func checkNotRoot() error {
	if os.Getuid() == 0 {
		if os.Getenv("SUDO_USER") != "" {
			return fmt.Errorf("pmux agent must be installed as your regular user, not with sudo\n  Run without sudo: pmux agent install")
		}
		return fmt.Errorf("pmux agent must be installed as your regular user, not as root\n  Run as your normal user: pmux agent install")
	}
	return nil
}

// launchctlHint translates common launchctl error output into actionable
// messages for the end user. Returns empty string if no specific hint applies.
func launchctlHint(output string, exitCode int) string {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "domain does not support specified action"):
		// Exit 125 — typically caused by running as root or targeting wrong domain.
		return "The launchd GUI domain is not available. This usually means the command was run as root or via sudo.\n  Run without sudo: pmux agent install"
	case strings.Contains(lower, "could not find specified service"):
		return "The service is not loaded. Try reinstalling: pmux agent install"
	case strings.Contains(lower, "operation not permitted"):
		return "Permission denied by launchd. Check that your user has permission to manage LaunchAgents."
	case strings.Contains(lower, "no such file or directory"):
		return "The service plist file is missing. Try reinstalling: pmux agent install"
	case exitCode == 125:
		// Catch-all for exit 125 without a recognized message.
		return "launchd rejected the operation (exit 125). Try: pmux agent uninstall && pmux agent install"
	}
	return ""
}

// wrapLaunchctlError creates an error from a launchctl command failure,
// appending an actionable hint when one is available.
func wrapLaunchctlError(verb, output string, err error) error {
	outStr := strings.TrimSpace(output)

	// Extract exit code from *exec.ExitError if available.
	exitCode := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		exitCode = exitErr.ExitCode()
	}

	hint := launchctlHint(outStr, exitCode)
	if hint != "" {
		return fmt.Errorf("launchctl %s: %s: %w\n  %s", verb, outStr, err, hint)
	}
	return fmt.Errorf("launchctl %s: %s: %w", verb, outStr, err)
}

func (m *launchdManager) Install() error {
	if err := checkNotRoot(); err != nil {
		return err
	}

	if err := m.writePlist(); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}

	// bootstrap loads and starts the service
	uid := os.Getuid()
	cmd := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", uid), m.plistPath())
	if out, err := cmd.CombinedOutput(); err != nil {
		outStr := strings.TrimSpace(string(out))
		// If already bootstrapped, bootout first then re-bootstrap to pick up
		// any plist changes (e.g., updated binary path).
		// Exit code 5 (I/O error) is launchd's way of saying the label is
		// already loaded in this domain.
		if strings.Contains(outStr, "already bootstrapped") ||
			strings.Contains(outStr, "service already loaded") ||
			strings.Contains(outStr, "Input/output error") {
			_ = m.Uninstall()
			if err := m.writePlist(); err != nil {
				return fmt.Errorf("rewrite plist: %w", err)
			}
			cmd2 := exec.Command("launchctl", "bootstrap", fmt.Sprintf("gui/%d", uid), m.plistPath())
			if out2, err2 := cmd2.CombinedOutput(); err2 != nil {
				return wrapLaunchctlError("re-bootstrap", string(out2), err2)
			}
			return nil
		}
		return wrapLaunchctlError("bootstrap", string(out), err)
	}
	return nil
}

func (m *launchdManager) Uninstall() error {
	uid := os.Getuid()
	// bootout stops and unloads the service
	exec.Command("launchctl", "bootout", fmt.Sprintf("gui/%d/%s", uid, launchdLabel)).Run() //nolint:errcheck
	// Remove plist file
	if err := os.Remove(m.plistPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove plist: %w", err)
	}
	return nil
}

func (m *launchdManager) Start() error {
	if err := checkNotRoot(); err != nil {
		return err
	}

	uid := os.Getuid()
	domain := fmt.Sprintf("gui/%d", uid)
	target := fmt.Sprintf("%s/%s", domain, launchdLabel)

	// Try kickstart first (works if service is loaded but not running).
	cmd := exec.Command("launchctl", "kickstart", target)
	if _, err := cmd.CombinedOutput(); err == nil {
		return nil
	}

	// Service not loaded — re-bootstrap from plist.
	if err := m.writePlist(); err != nil {
		return fmt.Errorf("write plist: %w", err)
	}
	cmd = exec.Command("launchctl", "bootstrap", domain, m.plistPath())
	if out, err := cmd.CombinedOutput(); err != nil {
		return wrapLaunchctlError("bootstrap", string(out), err)
	}
	return nil
}

func (m *launchdManager) Stop() error {
	if err := checkNotRoot(); err != nil {
		return err
	}

	// Use bootout to fully unload the service from the launchd domain.
	// "launchctl kill SIGTERM" only sends a signal — launchd restarts the
	// service immediately due to KeepAlive. bootout unloads the job so it
	// stays stopped until Start()/Install() re-bootstraps it.
	uid := os.Getuid()
	target := fmt.Sprintf("gui/%d/%s", uid, launchdLabel)
	cmd := exec.Command("launchctl", "bootout", target)
	if out, err := cmd.CombinedOutput(); err != nil {
		outStr := strings.TrimSpace(string(out))
		// Not loaded / not found is not an error when stopping.
		if strings.Contains(outStr, "Could not find specified service") ||
			strings.Contains(outStr, "No such process") {
			return nil
		}
		return wrapLaunchctlError("bootout", string(out), err)
	}
	return nil
}

func (m *launchdManager) Status() (Status, error) {
	uid := os.Getuid()
	cmd := exec.Command("launchctl", "print", fmt.Sprintf("gui/%d/%s", uid, launchdLabel))
	out, err := cmd.CombinedOutput()
	if err != nil {
		if !m.IsInstalled() {
			return Status{Installed: false}, nil
		}
		return Status{Installed: true, Running: false}, nil
	}

	s := Status{Installed: true}
	// Parse PID from launchctl print output
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "pid = ") {
			pidStr := strings.TrimPrefix(line, "pid = ")
			if pid, err := strconv.Atoi(pidStr); err == nil && pid > 0 {
				s.Running = true
				s.PID = pid
			}
		}
	}
	return s, nil
}

func (m *launchdManager) IsInstalled() bool {
	_, err := os.Stat(m.plistPath())
	return err == nil
}
