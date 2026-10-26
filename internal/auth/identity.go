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
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// RemoveKeyFiles deletes the files pmux writes to keysDir, then removes the
// directory only if it is now empty. It never deletes foreign files, since
// keysDir is user-configurable (identity.key_path) and may be e.g. $HOME.
func RemoveKeyFiles(keysDir string) error {
	for _, name := range []string{publicKeyFile, secretsFileName, fallbackKeyFileName} {
		if err := os.Remove(filepath.Join(keysDir, name)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", name, err)
		}
	}
	_ = os.Remove(keysDir) // fails harmlessly if other files remain
	return nil
}

// ErrNoIdentity is returned by CheckIdentity when no keypair exists.
var ErrNoIdentity = errors.New("no identity found; run 'pmux init' first")

// CheckIdentity reports whether an Ed25519 keypair exists. It returns
// ErrNoIdentity when the public key is missing on disk or the private key is
// missing from the SecretStore, and the wrapped store error when the store
// fails for any other reason (e.g. a locked keychain), so an unreadable
// identity is never mistaken for a missing one. The store is read at most once.
func CheckIdentity(keysDir string, store SecretStore) error {
	// Check public key on disk first so a fresh host never touches the store
	pubPath := filepath.Join(keysDir, publicKeyFile)
	if _, err := os.Stat(pubPath); err != nil {
		return ErrNoIdentity
	}

	// Check private key in secure store
	if _, err := store.Get(SecretKeyEd25519Private); err != nil {
		if errors.Is(err, ErrSecretNotFound) {
			return ErrNoIdentity
		}
		return fmt.Errorf("read identity from secret store: %w", err)
	}
	return nil
}

// HasIdentity checks whether an Ed25519 keypair exists.
// The private key is checked in the SecretStore and the public key on disk.
func HasIdentity(keysDir string, store SecretStore) bool {
	return CheckIdentity(keysDir, store) == nil
}

// challengeMessagePrefix versions the origin-bound token exchange challenge.
const challengeMessagePrefix = "pocketmux-auth-v1"

// canonicalOrigin reduces serverURL to scheme://host[:port]: scheme and host
// lowercased, default ports (443 for https, 80 for http) omitted, IPv6 hosts
// bracketed, and path, query and fragment dropped. URLs carrying userinfo are
// rejected. The result must match the server's and mobile's derivation.
func canonicalOrigin(serverURL string) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", fmt.Errorf("parse server URL: %w", err)
	}
	if u.Scheme == "" {
		return "", errors.New("server URL has no scheme")
	}
	if u.User != nil {
		return "", errors.New("server URL must not contain userinfo")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("server URL has no host")
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port), nil
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return scheme + "://" + host, nil
}

// SignChallenge signs the origin-bound token exchange challenge:
// "pocketmux-auth-v1|" + origin + "|" + deviceID + "|" + nonce, where origin is
// the canonical server origin (see canonicalOrigin). Binding the origin stops a
// signature obtained from one server from being replayed against another.
// Returns the base64-encoded signature.
func (id *Identity) SignChallenge(origin, deviceID, nonce string) string {
	message := []byte(challengeMessagePrefix + "|" + origin + "|" + deviceID + "|" + nonce)
	sig := ed25519.Sign(id.PrivateKey, message)
	return base64.StdEncoding.EncodeToString(sig)
}

// Ed25519PublicKeyBase64 returns the base64-encoded Ed25519 public key for server registration.
func (id *Identity) Ed25519PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(id.Ed25519PublicKey)
}

// deviceIDPattern matches a valid device ID: exactly 32 lowercase hex characters.
var deviceIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidateDeviceID checks that a device ID matches the expected format produced
// by deriveDeviceID: exactly 32 lowercase hex characters (SHA-256 first 16 bytes).
// Returns an error describing the validation failure, or nil if valid.
func ValidateDeviceID(id string) error {
	if len(id) != 32 {
		return fmt.Errorf("invalid device ID: must be 32 hex characters, got %d chars", len(id))
	}
	if !deviceIDPattern.MatchString(id) {
		return fmt.Errorf("invalid device ID: contains non-hex characters")
	}
	return nil
}

// deriveDeviceID computes a hex-encoded fingerprint from an Ed25519 public key.
// Uses the first 16 bytes of SHA-256(publicKey) → 32 hex characters.
func deriveDeviceID(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	return hex.EncodeToString(hash[:16])
}
