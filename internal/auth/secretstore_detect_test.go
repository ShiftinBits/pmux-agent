package auth

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

// newTestLogger returns a logger that discards all output, suitable for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewSecretStore_FileBackend(t *testing.T) {
	tmpDir := t.TempDir()
	logger := newTestLogger()

	store, err := NewSecretStore(tmpDir, "file", logger)
	if err != nil {
		t.Fatalf("NewSecretStore(file) unexpected error: %v", err)
	}
	// FileSecretStore.Backend() returns "encrypted-file"
	if got := store.Backend(); got != "encrypted-file" {
		t.Errorf("Backend() = %q, want %q", got, "encrypted-file")
	}
}

func TestNewSecretStore_UnknownBackend(t *testing.T) {
	tmpDir := t.TempDir()
	logger := newTestLogger()

	_, err := NewSecretStore(tmpDir, "invalid", logger)
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
	if !strings.Contains(err.Error(), "unknown secret backend") {
		t.Errorf("error %q does not contain %q", err.Error(), "unknown secret backend")
	}
}

func TestNewSecretStore_AutoBackend(t *testing.T) {
	tmpDir := t.TempDir()
	logger := newTestLogger()

	store, err := NewSecretStore(tmpDir, "auto", logger)
	if err != nil {
		t.Fatalf("NewSecretStore(auto) unexpected error: %v", err)
	}
	if got := store.Backend(); got == "" {
		t.Error("Backend() returned empty string for auto backend")
	}
}

func TestNewSecretStore_EmptyBackend(t *testing.T) {
	tmpDir := t.TempDir()
	logger := newTestLogger()

	store, err := NewSecretStore(tmpDir, "", logger)
	if err != nil {
		t.Fatalf("NewSecretStore(\"\") unexpected error: %v", err)
	}
	if got := store.Backend(); got == "" {
		t.Error("Backend() returned empty string for empty-string backend preference")
	}
}

func TestNewSecretStore_KeyringBackend_Unavailable(t *testing.T) {
	if err := ProbeKeyring(); err == nil {
		t.Skip("keyring is available on this system — skipping unavailable test")
	}

	tmpDir := t.TempDir()
	logger := newTestLogger()

	_, err := NewSecretStore(tmpDir, "keyring", logger)
	if err == nil {
		t.Fatal("expected error when keyring is unavailable, got nil")
	}
	if !strings.Contains(err.Error(), "keyring backend requested but unavailable") {
		t.Errorf("error %q does not contain %q", err.Error(), "keyring backend requested but unavailable")
	}
}

func TestNewSecretStore_KeyringBackend_Available(t *testing.T) {
	if err := ProbeKeyring(); err != nil {
		t.Skipf("keyring not available on this system: %v", err)
	}

	tmpDir := t.TempDir()
	logger := newTestLogger()

	store, err := NewSecretStore(tmpDir, "keyring", logger)
	if err != nil {
		t.Fatalf("NewSecretStore(keyring) unexpected error: %v", err)
	}
	if got := store.Backend(); got != "keyring" {
		t.Errorf("Backend() = %q, want %q", got, "keyring")
	}
}

func TestFileSecretStore_Backend(t *testing.T) {
	tmpDir := t.TempDir()
	logger := newTestLogger()

	store := NewFileSecretStore(tmpDir, logger)
	if got := store.Backend(); got != "encrypted-file" {
		t.Errorf("Backend() = %q, want %q", got, "encrypted-file")
	}
}

func TestKeyringSecretStore_Backend(t *testing.T) {
	if err := ProbeKeyring(); err != nil {
		t.Skipf("keyring not available on this system: %v", err)
	}

	store := NewKeyringSecretStore()
	if got := store.Backend(); got != "keyring" {
		t.Errorf("Backend() = %q, want %q", got, "keyring")
	}
}
