package agent

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

// EnsureRunning checks if the agent is already running and starts it if not.
// Returns nil if the agent is running (or was started successfully).
// Does nothing if no identity exists (agent can't authenticate without one).
func EnsureRunning(paths config.Paths) error {
	// No identity — agent can't authenticate
	if !auth.HasIdentity(paths.KeysDir) {
		return nil
	}

	pidFile := PIDFilePath(paths)

	// TODO: There's a TOCTOU race between the running check and spawn. Two concurrent
	// pmux commands could both pass the check and spawn two agents. Use file
	// locking (syscall.Flock) in a future phase to make this atomic.
	pid, err := ReadPIDFile(pidFile)
	if err == nil && IsProcessRunning(pid) {
		return nil
	}

	return spawn(pidFile)
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
		return fmt.Errorf("start agent: %w", err)
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
