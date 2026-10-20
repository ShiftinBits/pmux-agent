package agent

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantSocket string
		wantLog    string
	}{
		{"valid config", "[tmux]\nsocket_name = \"work\"\n", "work", ""},
		// Invalid values only warn: the user's other settings (socket) must survive.
		{"invalid config is advisory", "log_level = \"verbose\"\n[tmux]\nsocket_name = \"work\"\n", "work", "invalid config"},
		{"unparseable config falls back to defaults", "not = [valid toml", "pmux", "using defaults"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			cfg := loadConfig(path, slog.New(slog.NewTextHandler(&logs, nil)))

			if cfg.Tmux.SocketName != tt.wantSocket {
				t.Errorf("SocketName = %q, want %q", cfg.Tmux.SocketName, tt.wantSocket)
			}
			if tt.wantLog == "" && logs.Len() > 0 {
				t.Errorf("unexpected log output: %s", logs.String())
			}
			if !strings.Contains(logs.String(), tt.wantLog) {
				t.Errorf("log = %q, want it to contain %q", logs.String(), tt.wantLog)
			}
		})
	}
}
