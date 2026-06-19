//go:build !darwin && !linux

package agent

import (
	"context"
	"log/slog"
	"runtime"
)

// startKeepAwake is a no-op on platforms without a supported sleep inhibitor.
// The agent only targets macOS and Linux hosts; this keeps the build green
// elsewhere.
func startKeepAwake(_ context.Context, logger *slog.Logger) {
	logger.Warn("keep_awake enabled but unsupported on this platform", "os", runtime.GOOS)
}
