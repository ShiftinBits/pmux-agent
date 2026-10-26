//go:build !linux && !darwin

package agent

import (
	"context"
	"log/slog"
)

// startSleepWatcher is a no-op on platforms without a sleep hook (Windows/WSL);
// the server's idle timeout is the offline-detection backstop there.
func startSleepWatcher(_ context.Context, logger *slog.Logger, _ bool, _, _ func()) {
	logger.Debug("sleep watcher not supported on this platform; relying on the server idle timeout")
}
