package agent

import (
	"context"
	"log/slog"
	"time"
)

const (
	// tmuxMonitorInterval is how often the agent checks tmux server state.
	tmuxMonitorInterval = 2 * time.Second
)

// monitorTmux periodically checks if the tmux server is running on the pmux
// socket and calls setRunning with the current state. Unlike the old watchTmux,
// this never triggers agent shutdown — the agent runs independently of tmux.
// Logs state transitions only.
func monitorTmux(ctx context.Context, tc serverChecker, setRunning func(bool), pollInterval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	wasRunning := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			running := tc.IsServerRunning()
			setRunning(running)

			if running && !wasRunning {
				logger.Info("tmux server detected")
			} else if !running && wasRunning {
				logger.Info("tmux server exited")
			}
			wasRunning = running
		}
	}
}
