package auth

import (
	"fmt"
	"log/slog"
)

const (
	// BackendAuto probes the system keyring, falling back to encrypted file.
	BackendAuto = "auto"

	// BackendKeyring forces the system keyring backend. Errors if unavailable.
	BackendKeyring = "keyring"

	// BackendFile forces the encrypted file backend.
	BackendFile = "file"
)

// NewSecretStore creates a SecretStore based on the backend preference.
//
// Supported values for backendPref:
//   - "auto" (default): probe system keyring, fall back to encrypted file
//   - "keyring": require system keyring, error if unavailable
//   - "file": use encrypted file, skip keyring even if available
//
// keysDir is the directory for the encrypted file fallback (e.g., ~/.config/pmux/keys/).
func NewSecretStore(keysDir string, backendPref string) (SecretStore, error) {
	switch backendPref {
	case BackendKeyring:
		if err := ProbeKeyring(); err != nil {
			return nil, fmt.Errorf("keyring backend requested but unavailable: %w", err)
		}
		store := NewKeyringSecretStore()
		slog.Info("secret store initialized", "backend", store.Backend())
		return store, nil

	case BackendFile:
		store := NewFileSecretStore(keysDir)
		slog.Info("secret store initialized", "backend", store.Backend())
		return store, nil

	case BackendAuto, "":
		// Try keyring first
		if err := ProbeKeyring(); err == nil {
			store := NewKeyringSecretStore()
			slog.Info("secret store initialized", "backend", store.Backend())
			return store, nil
		}
		// Fall back to encrypted file
		store := NewFileSecretStore(keysDir)
		slog.Info("secret store initialized",
			"backend", store.Backend(),
			"reason", "system keyring unavailable, using encrypted file",
		)
		return store, nil

	default:
		return nil, fmt.Errorf("unknown secret backend: %q (use %q, %q, or %q)",
			backendPref, BackendAuto, BackendKeyring, BackendFile)
	}
}
