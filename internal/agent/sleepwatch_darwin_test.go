package agent

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// messageHandler is a slog.Handler that forwards each record's message to a
// channel so a test can wait for specific log lines.
type messageHandler struct {
	messages chan<- string
}

func (h messageHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h messageHandler) Handle(_ context.Context, r slog.Record) error {
	select {
	case h.messages <- r.Message:
	default:
	}
	return nil
}

func (h messageHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h messageHandler) WithGroup(string) slog.Handler { return h }

// waitForMessage blocks until msg is logged or timeout elapses.
func waitForMessage(t *testing.T, messages <-chan string, msg string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case got := <-messages:
			if got == msg {
				return
			}
		case <-deadline:
			t.Fatalf("timed out after %v waiting for log %q", timeout, msg)
		}
	}
}

// The darwin watcher must start without blocking the caller and stop its run
// loop when ctx is cancelled, even if cancelled before the run loop starts.
// keepAwake must not skip it: caffeinate -i doesn't block lid-close or forced
// sleeps, which still deliver IOKit notifications.
func TestStartSleepWatcher_Darwin_StartsAndStops(t *testing.T) {
	const (
		started = "sleep watcher started: will notify the signaling server before the host sleeps"
		stopped = "sleep watcher stopped"
	)
	tests := []struct {
		name      string
		keepAwake bool
		// cancelEarly cancels ctx right after startSleepWatcher returns, before
		// the run loop is known to be running, so a CFRunLoopStop issued before
		// CFRunLoopRun must not be lost.
		cancelEarly bool
	}{
		{"keep_awake off", false, false},
		{"keep_awake on does not skip", true, false},
		{"cancel before run loop starts", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messages := make(chan string, 16)
			logger := slog.New(messageHandler{messages: messages})
			called := make(chan struct{}, 1)
			mark := func() {
				select {
				case called <- struct{}{}:
				default:
				}
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			done := make(chan struct{})
			go func() {
				startSleepWatcher(ctx, logger, tt.keepAwake, mark, mark)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("startSleepWatcher did not return promptly")
			}

			if tt.cancelEarly {
				cancel()
			}
			waitForMessage(t, messages, started, 2*time.Second)
			if !tt.cancelEarly {
				// The run loop must block until ctx is cancelled; returning on its
				// own would mean the notification source was never added.
				select {
				case got := <-messages:
					if got == stopped {
						t.Fatal("run loop exited before ctx was cancelled")
					}
				case <-time.After(200 * time.Millisecond):
				}
			}
			cancel()
			waitForMessage(t, messages, stopped, 2*time.Second)

			// No real sleep or wake happened, so neither callback may fire.
			select {
			case <-called:
				t.Error("sleep/resume callback invoked without a power event")
			default:
			}
		})
	}
}
