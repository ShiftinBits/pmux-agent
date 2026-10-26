package agent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestSenderTrusted(t *testing.T) {
	errLookup := errors.New("lookup failed")
	tests := []struct {
		name      string
		sender    string
		owner     string
		err       error
		lastOwner string
		want      bool
		wantKnown string
	}{
		{"lookup ok matching", ":1.42", ":1.42", nil, ":1.1", true, ":1.42"},
		{"lookup ok mismatch", ":1.99", ":1.42", nil, ":1.42", false, ":1.42"},
		{"lookup ok empty owner", ":1.42", "", nil, ":1.42", false, ""},
		{"lookup fails, matches last owner", ":1.42", "", errLookup, ":1.42", true, ":1.42"},
		{"lookup fails, differs from last owner", ":1.99", "", errLookup, ":1.42", false, ":1.42"},
		{"lookup fails, no last owner", ":1.42", "", errLookup, "", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, known := senderTrusted(tt.sender, tt.owner, tt.err, tt.lastOwner)
			if got != tt.want || known != tt.wantKnown {
				t.Errorf("senderTrusted() = (%v, %q), want (%v, %q)", got, known, tt.want, tt.wantKnown)
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
