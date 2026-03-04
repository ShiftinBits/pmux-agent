package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// secretsFileName is the encrypted secrets file name.
	secretsFileName = "secrets.enc"

	// fileVersion is the current encrypted file format version.
	fileVersion byte = 0x01

	// Argon2id parameters for key derivation.
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 4
	argonKeyLen  = 32 // 256-bit key for XChaCha20-Poly1305

	// Salt and nonce sizes.
	saltSize  = 16
	nonceSize = chacha20poly1305.NonceSizeX // 24 bytes

	// machineIDApp is the application-specific key for HMAC of machine ID.
	machineIDApp = "pocketmux-agent-v1"

	// fallbackKeyFileName is the file used to store a generated machine ID fallback.
	fallbackKeyFileName = "machine-id.key"

	// fallbackKeySize is the size of the generated fallback key in bytes.
	fallbackKeySize = 32
)

// FileSecretStore stores secrets in an encrypted file on disk.
// Encryption uses XChaCha20-Poly1305 with a key derived via Argon2id from
// the machine's unique identifier.
type FileSecretStore struct {
	mu       sync.Mutex
	filePath string
	secrets  map[string][]byte
	loaded   bool
}

// NewFileSecretStore creates an encrypted file-backed secret store.
// The secrets file is stored in the given directory as "secrets.enc".
func NewFileSecretStore(keysDir string) *FileSecretStore {
	return &FileSecretStore{
		filePath: filepath.Join(keysDir, secretsFileName),
		secrets:  make(map[string][]byte),
	}
}

// Get retrieves a secret from the encrypted file.
func (f *FileSecretStore) Get(key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.ensureLoaded(); err != nil {
		return nil, err
	}

	data, ok := f.secrets[key]
	if !ok {
		return nil, ErrSecretNotFound
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	return cp, nil
}

// Set stores a secret in the encrypted file.
func (f *FileSecretStore) Set(key string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.ensureLoaded(); err != nil {
		return err
	}

	cp := make([]byte, len(data))
	copy(cp, data)
	f.secrets[key] = cp

	return f.flush()
}

// Delete removes a secret from the encrypted file.
func (f *FileSecretStore) Delete(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.ensureLoaded(); err != nil {
		return err
	}

	delete(f.secrets, key)
	return f.flush()
}

// Backend returns "encrypted-file".
func (f *FileSecretStore) Backend() string {
	return "encrypted-file"
}

// ensureLoaded reads and decrypts the secrets file on first access.
// Must be called with f.mu held.
func (f *FileSecretStore) ensureLoaded() error {
	if f.loaded {
		return nil
	}

	data, err := os.ReadFile(f.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			// No file yet — start with empty store
			f.secrets = make(map[string][]byte)
			f.loaded = true
			return nil
		}
		return fmt.Errorf("read secrets file: %w", err)
	}

	if err := f.decrypt(data); err != nil {
		return fmt.Errorf("decrypt secrets: %w", err)
	}
	f.loaded = true
	return nil
}

// flush encrypts and writes the secrets to disk.
// Must be called with f.mu held.
func (f *FileSecretStore) flush() error {
	data, err := f.encrypt()
	if err != nil {
		return fmt.Errorf("encrypt secrets: %w", err)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(f.filePath), 0700); err != nil {
		return fmt.Errorf("create keys directory: %w", err)
	}

	if err := os.WriteFile(f.filePath, data, 0600); err != nil {
		return fmt.Errorf("write secrets file: %w", err)
	}
	return nil
}

// encrypt serializes and encrypts the secrets map.
func (f *FileSecretStore) encrypt() ([]byte, error) {
	plaintext, err := json.Marshal(f.secrets)
	if err != nil {
		return nil, fmt.Errorf("marshal secrets: %w", err)
	}

	// Generate random salt for KDF
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Derive encryption key
	machineID, err := getMachineID(filepath.Dir(f.filePath))
	if err != nil {
		return nil, fmt.Errorf("get machine ID: %w", err)
	}
	encKey := deriveKey(machineID, salt)

	// Create AEAD cipher
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	// Assemble file: version + salt + nonce + ciphertext
	out := make([]byte, 0, 1+saltSize+nonceSize+len(ciphertext))
	out = append(out, fileVersion)
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)

	return out, nil
}

// decrypt parses and decrypts the secrets file data.
func (f *FileSecretStore) decrypt(data []byte) error {
	minLen := 1 + saltSize + nonceSize + chacha20poly1305.Overhead
	if len(data) < minLen {
		return fmt.Errorf("secrets file too small: %d bytes", len(data))
	}

	version := data[0]
	if version != fileVersion {
		return fmt.Errorf("unsupported secrets file version: %d", version)
	}

	salt := data[1 : 1+saltSize]
	nonce := data[1+saltSize : 1+saltSize+nonceSize]
	ciphertext := data[1+saltSize+nonceSize:]

	// Derive decryption key
	machineID, err := getMachineID(filepath.Dir(f.filePath))
	if err != nil {
		return fmt.Errorf("get machine ID: %w", err)
	}
	encKey := deriveKey(machineID, salt)

	// Create AEAD cipher
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decrypt failed (wrong machine or corrupted file): %w", err)
	}

	// Parse JSON
	secrets := make(map[string][]byte)
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return fmt.Errorf("parse decrypted secrets: %w", err)
	}

	f.secrets = secrets
	return nil
}

// deriveKey derives a 256-bit encryption key using Argon2id.
func deriveKey(machineID []byte, salt []byte) []byte {
	return argon2.IDKey(machineID, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// getMachineID returns a machine-bound identifier for key derivation.
// It tries platform-specific sources in order of preference, falling back to
// a random persistent key if no machine ID is available.
func getMachineID(keysDir string) ([]byte, error) {
	// Try platform-specific machine ID sources
	id, err := readMachineID()
	if err == nil && len(id) > 0 {
		// HMAC with application-specific key per freedesktop.org spec
		return hmacSHA256(id, machineIDApp), nil
	}

	// Fallback: generate and persist a random key
	return fallbackMachineID(keysDir)
}

// fallbackMachineID generates or reads a persistent random key used when no
// platform machine ID is available. The key is stored at keysDir/machine-id.key
// with mode 0600.
func fallbackMachineID(keysDir string) ([]byte, error) {
	keyPath := filepath.Join(keysDir, "machine-id.key")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		if len(data) != fallbackKeySize {
			return nil, fmt.Errorf("corrupt fallback machine ID key at %s: expected %d bytes, got %d", keyPath, fallbackKeySize, len(data))
		}
		return hmacSHA256(data, machineIDApp), nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read fallback machine ID key: %w", err)
	}

	// Generate new random key
	key := make([]byte, fallbackKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate fallback machine ID key: %w", err)
	}

	// Ensure directory exists
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("create keys directory for fallback key: %w", err)
	}

	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("write fallback machine ID key: %w", err)
	}

	slog.Warn("no platform machine ID available, using generated fallback", "path", keyPath)

	return hmacSHA256(key, machineIDApp), nil
}

// readMachineID reads the machine ID from platform-specific sources.
func readMachineID() ([]byte, error) {
	switch runtime.GOOS {
	case "darwin":
		return readMacOSMachineID()
	default:
		return readLinuxMachineID()
	}
}

// readLinuxMachineID reads /etc/machine-id or /var/lib/dbus/machine-id.
func readLinuxMachineID() ([]byte, error) {
	paths := []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
	}
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		id := strings.TrimSpace(string(data))
		if len(id) > 0 {
			return []byte(id), nil
		}
	}
	return nil, fmt.Errorf("no machine-id file found")
}

// readMacOSMachineID reads the IOPlatformUUID via ioreg.
// Uses a 5-second timeout to prevent blocking agent startup if ioreg hangs.
func readMacOSMachineID() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return nil, fmt.Errorf("ioreg: %w", err)
	}
	// Parse IOPlatformUUID from output
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				uuid := strings.TrimSpace(parts[1])
				uuid = strings.Trim(uuid, "\"")
				if len(uuid) > 0 {
					return []byte(uuid), nil
				}
			}
		}
	}
	return nil, fmt.Errorf("IOPlatformUUID not found in ioreg output")
}

// hmacSHA256 computes HMAC-SHA256(data, key).
func hmacSHA256(data []byte, key string) []byte {
	h := hmac.New(sha256.New, []byte(key))
	h.Write(data)
	return h.Sum(nil)
}
