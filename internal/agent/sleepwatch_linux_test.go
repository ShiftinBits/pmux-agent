package agent

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestIsFromLogind(t *testing.T) {
	tests := []struct {
		name   string
		sender string
		owner  string
		want   bool
	}{
		{"matching unique name", ":1.42", ":1.42", true},
		{"different sender", ":1.99", ":1.42", false},
		{"empty owner", ":1.42", "", false},
		{"empty sender and empty owner", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := &dbus.Signal{Sender: tt.sender}
			if got := isFromLogind(sig, tt.owner); got != tt.want {
				t.Errorf("isFromLogind(%q, %q) = %v, want %v", tt.sender, tt.owner, got, tt.want)
			}
		})
	}
}

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
