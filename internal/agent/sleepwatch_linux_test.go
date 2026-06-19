package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// When keep_awake is blocking sleep, startSleepWatcher must short-circuit
// without touching D-Bus or invoking the sleep/resume callbacks.
func TestStartSleepWatcher_SkippedWhenKeepAwake(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	called := make(chan struct{}, 1)
	mark := func() { called <- struct{}{} }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Must return promptly (no bus connect, no goroutine doing work).
	done := make(chan struct{})
	go func() {
		startSleepWatcher(ctx, logger, true, mark, mark)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("startSleepWatcher did not return promptly with keepAwake=true")
	}

	// Neither callback should ever fire on the skip path.
	select {
	case <-called:
		t.Error("sleep/resume callback invoked despite keepAwake=true")
	case <-time.After(100 * time.Millisecond):
	}
}
