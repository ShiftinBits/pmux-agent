package agent

import (
	"errors"
	"fmt"
	"sync"
	"testing"
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

func TestFatalInitError_Error(t *testing.T) {
	inner := errors.New("config file missing")
	err := &FatalInitError{Err: inner}

	if got := err.Error(); got != "config file missing" {
		t.Errorf("FatalInitError.Error() = %q, want %q", got, "config file missing")
	}
}

func TestFatalInitError_Unwrap(t *testing.T) {
	inner := errors.New("secret store unavailable")
	err := &FatalInitError{Err: inner}

	if got := err.Unwrap(); got != inner {
		t.Errorf("FatalInitError.Unwrap() = %v, want %v", got, inner)
	}
}

func TestIsFatalInitError(t *testing.T) {
	t.Run("direct FatalInitError", func(t *testing.T) {
		err := &FatalInitError{Err: errors.New("init failed")}
		if !IsFatalInitError(err) {
			t.Error("IsFatalInitError() = false, want true for *FatalInitError")
		}
	})

	t.Run("regular error", func(t *testing.T) {
		err := errors.New("ordinary error")
		if IsFatalInitError(err) {
			t.Error("IsFatalInitError() = true, want false for plain error")
		}
	})

	t.Run("nil error", func(t *testing.T) {
		if IsFatalInitError(nil) {
			t.Error("IsFatalInitError() = true, want false for nil")
		}
	})

	t.Run("wrapped FatalInitError via fmt.Errorf", func(t *testing.T) {
		inner := &FatalInitError{Err: errors.New("identity not found")}
		wrapped := fmt.Errorf("startup failed: %w", inner)
		if !IsFatalInitError(wrapped) {
			t.Error("IsFatalInitError() = false, want true for wrapped *FatalInitError")
		}
	})
}

