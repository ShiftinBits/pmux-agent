//go:build !linux

package agent

import (
	"context"
	"log/slog"
)

// startSleepWatcher is a no-op on platforms without a logind sleep hook. macOS
// would need IOKit sleep notifications (IORegisterForSystemPower); until then,
// the server's idle timeout is the offline-detection backstop there.
func startSleepWatcher(_ context.Context, logger *slog.Logger, _ bool, _, _ func()) {
	logger.Debug("sleep watcher not supported on this platform; relying on the server idle timeout")
}
