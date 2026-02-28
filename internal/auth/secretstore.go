// Package auth provides secure secret storage for cryptographic keys.
//
// SecretStore is the abstraction layer for storing secrets in the system
// keychain (macOS Keychain, Linux SecretService) or an encrypted file fallback.
package auth

import (
	"errors"
	"sync"
)

const (
	// ServiceName is the keychain/keyring service identifier.
	ServiceName = "pocketmux"

	// SecretKeyEd25519Private is the key name for the Ed25519 private key.
	SecretKeyEd25519Private = "ed25519-private-key"

	// SecretKeySharedSecretPrefix is the prefix for shared secret key names.
	// The full key is "shared-secret-<deviceId>".
	SecretKeySharedSecretPrefix = "shared-secret-"
)

// ErrSecretNotFound is returned when a secret does not exist in the store.
var ErrSecretNotFound = errors.New("secret not found")

// SecretStore provides secure storage for cryptographic secrets.
// Implementations may use the system keychain, encrypted files, or in-memory storage.
type SecretStore interface {
	// Get retrieves a secret by key. Returns ErrSecretNotFound if the key does not exist.
	Get(key string) ([]byte, error)

	// Set stores a secret under the given key. Overwrites any existing value.
	Set(key string, data []byte) error

	// Delete removes a secret by key. Returns nil if the key does not exist.
	Delete(key string) error

	// Backend returns the name of the active storage backend
	// (e.g., "keychain", "secret-service", "encrypted-file", "memory").
	Backend() string
}

// SharedSecretKey returns the full key name for a device's shared secret.
func SharedSecretKey(deviceID string) string {
	return SecretKeySharedSecretPrefix + deviceID
}

// MemorySecretStore is an in-memory SecretStore for testing.
type MemorySecretStore struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

// NewMemorySecretStore creates a new in-memory secret store.
func NewMemorySecretStore() *MemorySecretStore {
	return &MemorySecretStore{
		secrets: make(map[string][]byte),
	}
}

// Get retrieves a secret from memory.
func (m *MemorySecretStore) Get(key string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, ok := m.secrets[key]
	if !ok {
		return nil, ErrSecretNotFound
	}
	// Return a copy to prevent mutation
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

// Set stores a secret in memory.
func (m *MemorySecretStore) Set(key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cp := make([]byte, len(data))
	copy(cp, data)
	m.secrets[key] = cp
	return nil
}

// Delete removes a secret from memory.
func (m *MemorySecretStore) Delete(key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.secrets, key)
	return nil
}

// Backend returns "memory".
func (m *MemorySecretStore) Backend() string {
	return "memory"
}
