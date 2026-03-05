// Package auth handles Ed25519 keypair generation, storage, and challenge signing.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

const (
	publicKeyFile = "ed25519.pub"
	keyFilePerms  = 0600
)

// Identity holds an Ed25519 keypair and the derived device ID.
type Identity struct {
	PrivateKey       ed25519.PrivateKey
	Ed25519PublicKey ed25519.PublicKey
	DeviceID         string // hex-encoded SHA-256 fingerprint of public key (first 16 bytes)
}

// GenerateIdentity creates a new Ed25519 keypair, stores the private key in the
// SecretStore, and saves the public key to keysDir on disk.
func GenerateIdentity(keysDir string, store SecretStore) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 keypair: %w", err)
	}

	id := &Identity{
		PrivateKey:       priv,
		Ed25519PublicKey: pub,
		DeviceID:         deriveDeviceID(pub),
	}

	// Store private key in the secure store
	if err := store.Set(SecretKeyEd25519Private, []byte(priv)); err != nil {
		return nil, fmt.Errorf("store private key: %w", err)
	}

	// Save public key to disk (not secret, needed for display/diagnostics)
	pubPath := filepath.Join(keysDir, publicKeyFile)
	if err := os.WriteFile(pubPath, pub, keyFilePerms); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}

	return id, nil
}

// LoadIdentity loads an existing Ed25519 keypair. The private key is retrieved
// from the SecretStore and the public key is read from keysDir on disk.
func LoadIdentity(keysDir string, store SecretStore, logger *slog.Logger) (*Identity, error) {
	pubPath := filepath.Join(keysDir, publicKeyFile)

	// Check and fix permissions on public key file
	if err := enforceKeyFilePerms(pubPath, logger); err != nil {
		return nil, fmt.Errorf("enforce public key permissions: %w", err)
	}

	// Load private key from secure store
	privBytes, err := store.Get(SecretKeyEd25519Private)
	if err != nil {
		return nil, fmt.Errorf("load private key from %s backend: %w", store.Backend(), err)
	}

	// Load public key from disk
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: got %d, want %d", len(privBytes), ed25519.PrivateKeySize)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d, want %d", len(pubBytes), ed25519.PublicKeySize)
	}

	priv := ed25519.PrivateKey(privBytes)
	pub := ed25519.PublicKey(pubBytes)

	return &Identity{
		PrivateKey:       priv,
		Ed25519PublicKey: pub,
		DeviceID:         deriveDeviceID(pub),
	}, nil
}

// enforceKeyFilePerms checks that a key file has 0600 permissions.
// If the file is more permissive, it fixes the permissions and logs a warning.
func enforceKeyFilePerms(path string, logger *slog.Logger) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", filepath.Base(path), err)
	}

	perm := info.Mode().Perm()
	if perm != keyFilePerms {
		logger.Warn("insecure key file permissions detected, fixing",
			"file", filepath.Base(path),
			"was", fmt.Sprintf("%04o", perm),
			"fixed", fmt.Sprintf("%04o", keyFilePerms),
		)
		if err := os.Chmod(path, keyFilePerms); err != nil {
			return fmt.Errorf("chmod %s: %w", filepath.Base(path), err)
		}
	}

	return nil
}

// HasIdentity checks whether an Ed25519 keypair exists.
// The private key is checked in the SecretStore and the public key on disk.
func HasIdentity(keysDir string, store SecretStore) bool {
	// Check public key on disk
	pubPath := filepath.Join(keysDir, publicKeyFile)
	if _, err := os.Stat(pubPath); err != nil {
		return false
	}

	// Check private key in secure store
	_, err := store.Get(SecretKeyEd25519Private)
	return !errors.Is(err, ErrSecretNotFound) && err == nil
}

// SignChallenge signs the token exchange challenge: deviceId + timestamp.
// Returns the base64-encoded signature.
func (id *Identity) SignChallenge(deviceID string, timestamp string) string {
	message := []byte(deviceID + timestamp)
	sig := ed25519.Sign(id.PrivateKey, message)
	return base64.StdEncoding.EncodeToString(sig)
}

// Ed25519PublicKeyBase64 returns the base64-encoded Ed25519 public key for server registration.
func (id *Identity) Ed25519PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(id.Ed25519PublicKey)
}

// deriveDeviceID computes a hex-encoded fingerprint from an Ed25519 public key.
// Uses the first 16 bytes of SHA-256(publicKey) → 32 hex characters.
func deriveDeviceID(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	return hex.EncodeToString(hash[:16])
}
