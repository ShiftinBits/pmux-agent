package auth

import (
	"encoding/base64"
	"fmt"

	"github.com/zalando/go-keyring"
)

// KeyringSecretStore stores secrets in the system keychain/keyring.
// On macOS this uses Keychain, on Linux it uses the D-Bus Secret Service API
// (GNOME Keyring, KWallet, etc.).
type KeyringSecretStore struct {
	service string
}

// NewKeyringSecretStore creates a keyring-backed secret store.
func NewKeyringSecretStore() *KeyringSecretStore {
	return &KeyringSecretStore{
		service: ServiceName,
	}
}

// Get retrieves a secret from the system keyring.
// The stored value is base64-decoded since go-keyring only supports strings.
func (k *KeyringSecretStore) Get(key string) ([]byte, error) {
	encoded, err := keyring.Get(k.service, key)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil, ErrSecretNotFound
		}
		return nil, fmt.Errorf("keyring get %q: %w", key, err)
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("keyring decode %q: %w", key, err)
	}
	return data, nil
}

// Set stores a secret in the system keyring.
// The data is base64-encoded since go-keyring only supports strings.
func (k *KeyringSecretStore) Set(key string, data []byte) error {
	encoded := base64.StdEncoding.EncodeToString(data)
	if err := keyring.Set(k.service, key, encoded); err != nil {
		return fmt.Errorf("keyring set %q: %w", key, err)
	}
	return nil
}

// Delete removes a secret from the system keyring.
// Returns nil if the secret does not exist.
func (k *KeyringSecretStore) Delete(key string) error {
	err := keyring.Delete(k.service, key)
	if err != nil && err != keyring.ErrNotFound {
		return fmt.Errorf("keyring delete %q: %w", key, err)
	}
	return nil
}

// Backend returns the name of the keyring backend.
func (k *KeyringSecretStore) Backend() string {
	// go-keyring doesn't expose which backend is active,
	// so we return a generic name.
	return "keyring"
}

// ProbeKeyring tests whether the system keyring is available by writing
// and deleting a probe value. Returns nil if the keyring is usable.
func ProbeKeyring() error {
	const probeKey = "__probe__"
	const probeValue = "test"

	if err := keyring.Set(ServiceName, probeKey, probeValue); err != nil {
		return fmt.Errorf("keyring probe: %w", err)
	}
	// Clean up the probe entry
	_ = keyring.Delete(ServiceName, probeKey)
	return nil
}
