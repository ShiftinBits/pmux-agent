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

// EnsureRunning checks if the agent is already running and starts it if not.
// Returns nil if the agent is running (or was started successfully).
// Does nothing if no identity exists (agent can't authenticate without one).
func EnsureRunning(paths config.Paths, store auth.SecretStore) error {
	// No identity — agent can't authenticate
	if !auth.HasIdentity(paths.KeysDir, store) {
		return nil
	}

	pidFile := PIDFilePath(paths)

	// TODO: There's a TOCTOU race between the running check and spawn. Two concurrent
	// pmux commands could both pass the check and spawn two agents. Use file
	// locking (syscall.Flock) in a future phase to make this atomic.
	pid, err := ReadPIDFile(pidFile)
	if err == nil && IsProcessRunning(pid) {
		signalActivity(pid)
		return nil
	}

	return spawn(pidFile)
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

	cmd := exec.Command(exe, "--agent")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	// Start in a new session so it's not tied to the calling terminal
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start host: %w", err)
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
