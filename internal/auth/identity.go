// Package auth handles Ed25519 keypair generation, storage, and challenge signing.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

const (
	privateKeyFile = "ed25519.key"
	publicKeyFile  = "ed25519.pub"
	keyFilePerms   = 0600
)

// Identity holds an Ed25519 keypair and the derived device ID.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	DeviceID   string // hex-encoded SHA-256 fingerprint of public key (first 16 bytes)
}

// GenerateIdentity creates a new Ed25519 keypair and saves it to keysDir.
// The private key file is written with 0600 permissions.
func GenerateIdentity(keysDir string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Ed25519 keypair: %w", err)
	}

	id := &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
		DeviceID:   deriveDeviceID(pub),
	}

	if err := id.save(keysDir); err != nil {
		return nil, err
	}

	return id, nil
}

// LoadIdentity loads an existing Ed25519 keypair from keysDir.
func LoadIdentity(keysDir string) (*Identity, error) {
	privPath := filepath.Join(keysDir, privateKeyFile)
	pubPath := filepath.Join(keysDir, publicKeyFile)

	privBytes, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

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
		PrivateKey: priv,
		PublicKey:  pub,
		DeviceID:   deriveDeviceID(pub),
	}, nil
}

// HasIdentity checks whether an Ed25519 keypair exists in keysDir.
func HasIdentity(keysDir string) bool {
	privPath := filepath.Join(keysDir, privateKeyFile)
	pubPath := filepath.Join(keysDir, publicKeyFile)

	_, errPriv := os.Stat(privPath)
	_, errPub := os.Stat(pubPath)
	return errPriv == nil && errPub == nil
}

// SignChallenge signs the token exchange challenge: deviceId + timestamp.
// Returns the base64-encoded signature.
func (id *Identity) SignChallenge(deviceID string, timestamp string) string {
	message := []byte(deviceID + timestamp)
	sig := ed25519.Sign(id.PrivateKey, message)
	return base64.StdEncoding.EncodeToString(sig)
}

// PublicKeyBase64 returns the base64-encoded public key for server registration.
func (id *Identity) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(id.PublicKey)
}

// save writes the keypair to disk with appropriate permissions.
func (id *Identity) save(keysDir string) error {
	privPath := filepath.Join(keysDir, privateKeyFile)
	pubPath := filepath.Join(keysDir, publicKeyFile)

	if err := os.WriteFile(privPath, id.PrivateKey, keyFilePerms); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	if err := os.WriteFile(pubPath, id.PublicKey, keyFilePerms); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

// deriveDeviceID computes a hex-encoded fingerprint from an Ed25519 public key.
// Uses the first 16 bytes of SHA-256(publicKey) → 32 hex characters.
func deriveDeviceID(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	return hex.EncodeToString(hash[:16])
}
