package agent

import (
	"fmt"
	"io"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/service"
)

// RunAgentStart starts the PocketMux agent. It checks whether the agent is
// already running, tries the OS service manager if installed, and falls back
// to a direct spawn via EnsureRunning.
func RunAgentStart(paths config.Paths, store auth.SecretStore, mgr service.Manager, w io.Writer) error {
	// Check if already running
	pidFile := PIDFilePath(paths)
	if pid, err := ReadPIDFile(pidFile); err == nil && IsProcessRunning(pid) {
		fmt.Fprintf(w, "Agent is already running (PID %d)\n", pid)
		return nil
	}

	// Try service manager first
	if mgr.IsInstalled() {
		if err := mgr.Start(); err == nil {
			fmt.Fprintln(w, "Agent started (via service manager)")
			return nil
		}
		// Fall through to direct spawn
	}

	// Direct spawn — pass nil for mgr to force direct spawn (skip service)
	if err := EnsureRunning(paths, store, nil); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}
	fmt.Fprintln(w, "Agent started")
	return nil
}
