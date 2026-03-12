package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/service"
)

// ErrAgentNotRunning is returned when the agent is not running and the caller
// requested a stop. main.go maps this to exit code 1.
var ErrAgentNotRunning = errors.New("agent is not running")

// RunAgentStop stops the PocketMux agent. It tries the OS service manager
// first (if installed), then falls back to direct PID-based stop via SIGTERM
// with a SIGKILL fallback after 5 seconds.
//
// Returns ErrAgentNotRunning if no agent process is found.
// Returns nil on successful stop (including stale PID cleanup).
func RunAgentStop(paths config.Paths, mgr service.Manager, w io.Writer) error {
	// Try service manager first (prevents auto-restart)
	if mgr.IsInstalled() {
		if err := mgr.Stop(); err != nil {
			fmt.Fprintf(w, "⚠ service stop failed: %v\n", err)
			// Fall through to direct stop
		} else {
			fmt.Fprintln(w, "Agent stopped")
			return nil
		}
	}

	// Direct stop via PID file
	pidFile := PIDFilePath(paths)

	pid, err := ReadPIDFile(pidFile)
	if err != nil {
		return ErrAgentNotRunning
	}

	if !IsProcessRunning(pid) {
		fmt.Fprintln(w, "Agent is not running (stale PID file cleaned up)")
		RemovePIDFile(pidFile)
		return nil
	}

	process, ferr := os.FindProcess(pid)
	if ferr != nil {
		return fmt.Errorf("failed to find process %d: %w", pid, ferr)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("failed to send SIGTERM to PID %d: %w", pid, err)
	}

	// Wait up to 5 seconds for process to exit (poll every 200ms)
	const (
		stopTimeout  = 5 * time.Second
		pollInterval = 200 * time.Millisecond
	)

	deadline := time.After(stopTimeout)
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			// Process didn't exit in time - send SIGKILL
			if err := process.Signal(syscall.SIGKILL); err != nil {
				// Process may have exited between the last check and now
				if !IsProcessRunning(pid) {
					fmt.Fprintln(w, "Agent stopped")
					RemovePIDFile(pidFile)
					return nil
				}
				return fmt.Errorf("failed to send SIGKILL to PID %d: %w", pid, err)
			}
			fmt.Fprintln(w, "Agent forcefully killed")
			RemovePIDFile(pidFile)
			return nil
		case <-ticker.C:
			if !IsProcessRunning(pid) {
				fmt.Fprintln(w, "Agent stopped")
				RemovePIDFile(pidFile)
				return nil
			}
		}
	}
}
