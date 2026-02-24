package agent

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockServerChecker is a thread-safe mock for serverChecker.
type mockServerChecker struct {
	mu      sync.Mutex
	running bool
}

func (m *mockServerChecker) IsServerRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

func (m *mockServerChecker) setRunning(running bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.running = running
}

// fastConfig returns a watchConfig with very short intervals for testing.
func fastConfig() watchConfig {
	return watchConfig{
		startTimeout: 500 * time.Millisecond,
		startPoll:    20 * time.Millisecond,
		pollInterval: 50 * time.Millisecond,
		gracePeriod:  200 * time.Millisecond,
		gracePoll:    30 * time.Millisecond,
	}
}

func testLogger() *slog.Logger {
	return slog.Default()
}

func TestWatchTmux_GracePeriodExpires_CallsOnGraceExpired(t *testing.T) {
	mock := &mockServerChecker{running: true}
	cfg := fastConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var graceExpiredCalled atomic.Bool
	done := make(chan struct{})

	go func() {
		watchTmux(ctx, cancel, mock, func() {
			graceExpiredCalled.Store(true)
		}, cfg, testLogger())
		close(done)
	}()

	// Wait for watchTmux to detect the running server and enter monitoring
	time.Sleep(100 * time.Millisecond)

	// Simulate tmux server exit
	mock.setRunning(false)

	// Wait for grace period to expire and watchTmux to return
	select {
	case <-done:
		// watchTmux returned
	case <-time.After(2 * time.Second):
		t.Fatal("watchTmux did not return after grace period expired")
	}

	if !graceExpiredCalled.Load() {
		t.Error("expected onGraceExpired to be called")
	}

	// Context should be canceled
	if ctx.Err() == nil {
		t.Error("expected context to be canceled after grace period expired")
	}
}

func TestWatchTmux_ServerReappears_ResumesMonitoring(t *testing.T) {
	mock := &mockServerChecker{running: true}
	cfg := fastConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var graceExpiredCalled atomic.Bool

	go watchTmux(ctx, cancel, mock, func() {
		graceExpiredCalled.Store(true)
	}, cfg, testLogger())

	// Wait for watchTmux to enter monitoring
	time.Sleep(100 * time.Millisecond)

	// Simulate tmux server exit
	mock.setRunning(false)

	// Wait for grace period to start, then bring server back
	time.Sleep(80 * time.Millisecond)
	mock.setRunning(true)

	// Wait a bit longer — grace period should NOT expire
	time.Sleep(300 * time.Millisecond)

	if graceExpiredCalled.Load() {
		t.Error("onGraceExpired should NOT be called when server reappears")
	}

	// Context should still be alive
	if ctx.Err() != nil {
		t.Error("context should not be canceled when server reappeared")
	}
}

func TestWatchTmux_ServerReappears_ThenExitsAgain_ShutdownEventually(t *testing.T) {
	mock := &mockServerChecker{running: true}
	cfg := fastConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var graceExpiredCalled atomic.Bool
	done := make(chan struct{})

	go func() {
		watchTmux(ctx, cancel, mock, func() {
			graceExpiredCalled.Store(true)
		}, cfg, testLogger())
		close(done)
	}()

	// Wait for monitoring to start
	time.Sleep(100 * time.Millisecond)

	// First exit: server goes down, then comes back
	mock.setRunning(false)
	time.Sleep(80 * time.Millisecond)
	mock.setRunning(true)

	// Wait for resumption
	time.Sleep(150 * time.Millisecond)

	if graceExpiredCalled.Load() {
		t.Fatal("grace should not have expired after first exit")
	}

	// Second exit: server goes down permanently
	mock.setRunning(false)

	select {
	case <-done:
		// Good — watchTmux shut down
	case <-time.After(2 * time.Second):
		t.Fatal("watchTmux did not return after second exit")
	}

	if !graceExpiredCalled.Load() {
		t.Error("onGraceExpired should be called after permanent exit")
	}
}

func TestWatchTmux_ContextCanceled_ReturnsWithoutGraceExpired(t *testing.T) {
	mock := &mockServerChecker{running: true}
	cfg := fastConfig()

	ctx, cancel := context.WithCancel(context.Background())
	var graceExpiredCalled atomic.Bool
	done := make(chan struct{})

	go func() {
		watchTmux(ctx, cancel, mock, func() {
			graceExpiredCalled.Store(true)
		}, cfg, testLogger())
		close(done)
	}()

	// Wait for monitoring to start, then cancel externally
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// Good
	case <-time.After(2 * time.Second):
		t.Fatal("watchTmux did not return after context cancel")
	}

	if graceExpiredCalled.Load() {
		t.Error("onGraceExpired should not be called on external cancel")
	}
}

func TestWatchTmux_ServerNeverStarts_Timeout(t *testing.T) {
	mock := &mockServerChecker{running: false}
	cfg := fastConfig()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var graceExpiredCalled atomic.Bool
	done := make(chan struct{})

	go func() {
		watchTmux(ctx, cancel, mock, func() {
			graceExpiredCalled.Store(true)
		}, cfg, testLogger())
		close(done)
	}()

	select {
	case <-done:
		// Good — should timeout and return
	case <-time.After(2 * time.Second):
		t.Fatal("watchTmux did not return after start timeout")
	}

	if graceExpiredCalled.Load() {
		t.Error("onGraceExpired should not be called on start timeout")
	}

	// Context should be canceled (watchTmux calls cancel on timeout)
	if ctx.Err() == nil {
		t.Error("expected context to be canceled after start timeout")
	}
}

func TestGracePeriodExpired_ServerGone_ReturnsTrue(t *testing.T) {
	mock := &mockServerChecker{running: false}
	cfg := fastConfig()

	ctx := context.Background()
	result := gracePeriodExpired(ctx, mock, cfg, testLogger())

	if !result {
		t.Error("expected gracePeriodExpired to return true when server is gone")
	}
}

func TestGracePeriodExpired_ServerReappears_ReturnsFalse(t *testing.T) {
	mock := &mockServerChecker{running: false}
	cfg := fastConfig()

	ctx := context.Background()

	// Bring server back after a short delay
	go func() {
		time.Sleep(80 * time.Millisecond)
		mock.setRunning(true)
	}()

	result := gracePeriodExpired(ctx, mock, cfg, testLogger())

	if result {
		t.Error("expected gracePeriodExpired to return false when server reappears")
	}
}

func TestGracePeriodExpired_ContextCanceled_ReturnsFalse(t *testing.T) {
	mock := &mockServerChecker{running: false}
	cfg := fastConfig()

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel context after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	result := gracePeriodExpired(ctx, mock, cfg, testLogger())

	if result {
		t.Error("expected gracePeriodExpired to return false when context is canceled")
	}
}

func TestWatchConfig_Defaults(t *testing.T) {
	cfg := defaultWatchConfig()

	if cfg.startTimeout != tmuxStartTimeout {
		t.Errorf("startTimeout = %v, want %v", cfg.startTimeout, tmuxStartTimeout)
	}
	if cfg.pollInterval != tmuxPollInterval {
		t.Errorf("pollInterval = %v, want %v", cfg.pollInterval, tmuxPollInterval)
	}
	if cfg.gracePeriod != tmuxGracePeriod {
		t.Errorf("gracePeriod = %v, want %v", cfg.gracePeriod, tmuxGracePeriod)
	}
	if cfg.gracePoll != tmuxGracePollInterval {
		t.Errorf("gracePoll = %v, want %v", cfg.gracePoll, tmuxGracePollInterval)
	}
	if cfg.startPoll != tmuxStartPollInterval {
		t.Errorf("startPoll = %v, want %v", cfg.startPoll, tmuxStartPollInterval)
	}
}

func TestConstants_MatchSpec(t *testing.T) {
	// Spec requires 2s poll interval, 5s grace period, 1s grace poll
	if tmuxPollInterval != 2*time.Second {
		t.Errorf("tmuxPollInterval = %v, spec requires 2s", tmuxPollInterval)
	}
	if tmuxGracePeriod != 5*time.Second {
		t.Errorf("tmuxGracePeriod = %v, spec requires 5s", tmuxGracePeriod)
	}
	if tmuxGracePollInterval != 1*time.Second {
		t.Errorf("tmuxGracePollInterval = %v, spec requires 1s", tmuxGracePollInterval)
	}
}
