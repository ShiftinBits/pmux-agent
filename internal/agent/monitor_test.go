package agent

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestMonitorTmux_DetectsServerStart(t *testing.T) {
	mock := &mockServerChecker{running: false}
	var tmuxRunning atomic.Bool

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go monitorTmux(ctx, mock, tmuxRunning.Store, 20*time.Millisecond, slog.Default())

	if tmuxRunning.Load() {
		t.Error("expected tmuxRunning to be false initially")
	}

	mock.setRunning(true)
	time.Sleep(50 * time.Millisecond)

	if !tmuxRunning.Load() {
		t.Error("expected tmuxRunning to be true after server starts")
	}
}

func TestMonitorTmux_DetectsServerExit(t *testing.T) {
	mock := &mockServerChecker{running: true}
	var tmuxRunning atomic.Bool

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go monitorTmux(ctx, mock, tmuxRunning.Store, 20*time.Millisecond, slog.Default())

	time.Sleep(50 * time.Millisecond)
	if !tmuxRunning.Load() {
		t.Error("expected tmuxRunning to be true")
	}

	mock.setRunning(false)
	time.Sleep(50 * time.Millisecond)

	if tmuxRunning.Load() {
		t.Error("expected tmuxRunning to be false after server exits")
	}
}

func TestMonitorTmux_NeverCancelsContext(t *testing.T) {
	mock := &mockServerChecker{running: true}
	var tmuxRunning atomic.Bool

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go monitorTmux(ctx, mock, tmuxRunning.Store, 20*time.Millisecond, slog.Default())

	time.Sleep(50 * time.Millisecond)
	mock.setRunning(false)
	time.Sleep(100 * time.Millisecond)

	if ctx.Err() != nil {
		t.Error("monitorTmux should never cancel the context")
	}
}

func TestMonitorTmux_StopsOnContextCancel(t *testing.T) {
	mock := &mockServerChecker{running: true}
	var tmuxRunning atomic.Bool

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		monitorTmux(ctx, mock, tmuxRunning.Store, 20*time.Millisecond, slog.Default())
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("monitorTmux did not return after context cancel")
	}
}
