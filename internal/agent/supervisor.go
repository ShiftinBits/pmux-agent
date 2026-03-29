package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/service"
)

const (
	// stopTimeout is how long StopRunning waits for the agent to exit.
	stopTimeout = 3 * time.Second
	// stopPollInterval is how often StopRunning checks if the agent has exited.
	stopPollInterval = 100 * time.Millisecond
)

// signalActivity sends SIGUSR1 to wake the agent from dormancy.
// No-op if the signal can't be delivered (process exited between check and signal).
func signalActivity(pid int) {
	if proc, err := os.FindProcess(pid); err == nil {
		proc.Signal(syscall.SIGUSR1) //nolint:errcheck // Best-effort wake
	}
}

// signalReloadPairing sends SIGUSR2 to notify the running agent that pairing
// state has changed on disk and should be reloaded. Used after both pair and
// unpair operations. No-op if the signal can't be delivered.
func signalReloadPairing(pid int) {
	if proc, err := os.FindProcess(pid); err == nil {
		proc.Signal(syscall.SIGUSR2) //nolint:errcheck // Best-effort notification
	}
}

// EnsureRunning checks if the agent is already running and starts it if not.
// Returns nil if the agent is running (or was started successfully).
// Does nothing if no identity exists (agent can't authenticate without one).
// If mgr is non-nil and a service is installed, tries the service manager first.
//
// Uses flock on the PID file to serialize concurrent callers, preventing
// duplicate agent spawns from racing pmux commands.
func EnsureRunning(paths config.Paths, store auth.SecretStore, mgr service.Manager) error {
	// No identity — agent can't authenticate
	if !auth.HasIdentity(paths.KeysDir, store) {
		return nil
	}

	pidFile := PIDFilePath(paths)

	// Open (or create) the PID file for locking. The file must exist before
	// we can flock it, and we need a read/write handle for both the lock and
	// the subsequent PID write in spawn.
	f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_RDWR, pidFilePerms)
	if err != nil {
		return fmt.Errorf("open PID file for locking: %w", err)
	}
	defer f.Close() // Releases the flock

	// Acquire an exclusive lock. Concurrent callers block here until the
	// holder releases (via Close). This makes the check-and-spawn atomic.
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("acquire PID file lock: %w", err)
	}

	// Re-read PID under the lock — another process may have spawned
	// while we were waiting for the lock.
	pid, err := ReadPIDFile(pidFile)
	if err == nil && IsProcessRunning(pid) {
		signalActivity(pid)
		return nil
	}

	// Try service manager first
	if mgr != nil && mgr.IsInstalled() {
		if err := mgr.Start(); err == nil {
			// Wait briefly for agent to write PID file
			if waitForPID(pidFile, 3*time.Second) {
				return nil
			}
		}
		// Fall through to direct spawn if service start failed
	}

	return spawn(pidFile)
}

// waitForPID polls for the PID file to appear and contain a running process.
func waitForPID(pidFile string, timeout time.Duration) bool {
	deadline := time.After(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return false
		case <-ticker.C:
			pid, err := ReadPIDFile(pidFile)
			if err == nil && IsProcessRunning(pid) {
				return true
			}
		}
	}
}

// StopRunning stops the background agent if it is running.
// Returns nil if no agent was running or after a successful stop.
// Returns an error only if the agent could not be stopped.
func StopRunning(paths config.Paths) error {
	pidFile := PIDFilePath(paths)

	pid, err := ReadPIDFile(pidFile)
	if err != nil {
		// No PID file or unreadable — nothing to stop
		return nil
	}

	if !IsProcessRunning(pid) {
		RemovePIDFile(pidFile)
		return nil
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("find agent process %d: %w", pid, err)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		// Process may have exited between the check and signal
		if !IsProcessRunning(pid) {
			RemovePIDFile(pidFile)
			return nil
		}
		return fmt.Errorf("send SIGTERM to agent (PID %d): %w", pid, err)
	}

	// Poll for exit
	deadline := time.After(stopTimeout)
	ticker := time.NewTicker(stopPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			// Force kill as last resort
			_ = process.Signal(syscall.SIGKILL)
			RemovePIDFile(pidFile)
			return nil
		case <-ticker.C:
			if !IsProcessRunning(pid) {
				RemovePIDFile(pidFile)
				return nil
			}
		}
	}
}

// PIDFilePath returns the path to the agent PID file.
func PIDFilePath(paths config.Paths) string {
	return filepath.Join(paths.ConfigDir, pidFileName)
}

// spawn starts a new agent process in the background.
func spawn(pidFile string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find executable path: %w", err)
	}

	cmd := exec.Command(exe, "agent", "run")
	cmd.Stdin = nil
	cmd.Stdout = nil
	// Redirect stderr to agent log so early startup errors (before the
	// agent opens its own log handler) are captured for debugging.
	logPath := filepath.Join(filepath.Dir(pidFile), "agent.log")
	logFile, logErr := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if logErr == nil {
		cmd.Stderr = logFile
	} else {
		cmd.Stderr = nil
	}
	// Start in a new session so it's not tied to the calling terminal
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		if logFile != nil {
			logFile.Close()
		}
		return fmt.Errorf("start agent: %w", err)
	}

	// Close parent's copy of the log fd. The child inherited its own copy
	// via cmd.Start() which is unaffected by this close.
	if logFile != nil {
		logFile.Close()
	}

	// Write the child process PID so subsequent pmux commands can detect
	// the agent before it writes its own PID in Run().
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), pidFilePerms); err != nil {
		return fmt.Errorf("write PID file: %w", err)
	}

	// Release — don't wait for the background process
	cmd.Process.Release()

	return nil
}
