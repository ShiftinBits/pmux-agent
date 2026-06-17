package agent

import (
	"fmt"
	"io"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

// RunAgentStart starts the Pocketmux agent. It checks whether the agent is
// already running and otherwise spawns it directly via EnsureRunning.
func RunAgentStart(paths config.Paths, store auth.SecretStore, w io.Writer) error {
	// Check if already running
	pidFile := PIDFilePath(paths)
	if pid, err := ReadPIDFile(pidFile); err == nil && IsProcessRunning(pid) {
		fmt.Fprintf(w, "Agent is already running (PID %d)\n", pid)
		return nil
	}

	if err := EnsureRunning(paths, store); err != nil {
		return fmt.Errorf("failed to start agent: %w", err)
	}
	fmt.Fprintln(w, "Agent started")
	return nil
}
