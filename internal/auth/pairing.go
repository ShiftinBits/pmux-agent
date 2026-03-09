package auth

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/config"
	"golang.org/x/crypto/hkdf"
)

// MaxMobileNameLen is the maximum allowed length for a mobile device name.
// This limit is enforced during both initial pairing and name-update flows.
const MaxMobileNameLen = 64

// TruncateMobileName truncates a mobile device name to MaxMobileNameLen runes.
// It operates on Unicode code points to avoid splitting multi-byte characters.
func TruncateMobileName(name string) string {
	runes := []rune(name)
	if len(runes) > MaxMobileNameLen {
		return string(runes[:MaxMobileNameLen])
	}
	return name
}

// X25519Keypair holds an ephemeral X25519 keypair for key exchange during pairing.
type X25519Keypair struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
}

// PairedDevice stores information about a paired mobile device.
type PairedDevice struct {
	DeviceID     string    `json:"deviceId"`
	Name         string    `json:"name,omitempty"`
	SharedSecret string    `json:"-"` // base64-encoded X25519 shared secret (stored in SecretStore, not on disk)
	PairedAt     time.Time `json:"pairedAt"`
	// LastSeen is an int64 Unix timestamp (not time.Time) so that the zero
	// value 0 cleanly means "never seen" and omitempty suppresses it in JSON.
	// This matches the mobile side which stores lastSeen as a numeric timestamp.
	LastSeen int64 `json:"lastSeen,omitempty"`
}

// GenerateX25519Keypair creates a new ephemeral X25519 keypair for pairing.
func GenerateX25519Keypair() (*X25519Keypair, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate X25519 keypair: %w", err)
	}
	return &X25519Keypair{
		PrivateKey: priv,
		PublicKey:  priv.PublicKey(),
	}, nil
}

// PublicKeyBase64 returns the X25519 public key as a base64-encoded string.
func (kp *X25519Keypair) PublicKeyBase64() string {
	return base64.StdEncoding.EncodeToString(kp.PublicKey.Bytes())
}

// ComputeSharedSecret performs X25519 key exchange with the peer's public key.
// peerPubKeyBase64 is the base64-encoded X25519 public key from the peer.
// Returns the base64-encoded shared secret.
func (kp *X25519Keypair) ComputeSharedSecret(peerPubKeyBase64 string) (string, error) {
	peerBytes, err := base64.StdEncoding.DecodeString(peerPubKeyBase64)
	if err != nil {
		return "", fmt.Errorf("decode peer public key: %w", err)
	}

	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(peerBytes)
	if err != nil {
		return "", fmt.Errorf("parse peer X25519 public key: %w", err)
	}

	raw, err := kp.PrivateKey.ECDH(peerPub)
	if err != nil {
		return "", fmt.Errorf("compute X25519 shared secret: %w", err)
	}
	// Zero raw ECDH output after use — it is not uniformly distributed
	// and should not persist in memory. Note: the ephemeral PrivateKey
	// cannot be zeroed (crypto/ecdh exposes no API for this).
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()

	// Derive key material using HKDF (RFC 5869, §3.1 extract-then-expand).
	// Raw X25519 output is not uniformly distributed and must be processed
	// through a KDF before use. Salt (§3.3): static domain separator.
	// Info (§3.2): versioned context label for protocol isolation.
	hkdfReader := hkdf.New(sha256.New, raw, []byte("pocketmux"), []byte("pocketmux-pairing-v1"))
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derived); err != nil {
		return "", fmt.Errorf("derive shared secret via HKDF: %w", err)
	}

	return base64.StdEncoding.EncodeToString(derived), nil
}

// BuildQRPayload creates a pipe-delimited payload for the pairing QR code.
// Format: pairingCode|x25519PubKey|deviceId[|serverUrl]
// The server URL is omitted when it matches the production default to minimize
// QR code size. The mobile app falls back to the default when absent.
func BuildQRPayload(pairingCode string, x25519PubKeyBase64 string, hostDeviceID string, serverURL string) (string, error) {
	if serverURL == config.DefaultServerURL {
		return pairingCode + "|" + x25519PubKeyBase64 + "|" + hostDeviceID, nil
	}
	return pairingCode + "|" + x25519PubKeyBase64 + "|" + hostDeviceID + "|" + serverURL, nil
}

// LoadPairedDevices reads the paired devices list from disk and retrieves
// shared secrets from the SecretStore.
func LoadPairedDevices(path string, store SecretStore) ([]PairedDevice, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read paired devices: %w", err)
	}

	var devices []PairedDevice
	if err := json.Unmarshal(data, &devices); err != nil {
		return nil, fmt.Errorf("parse paired devices: %w", err)
	}

	// Retrieve shared secrets from the secure store
	for i := range devices {
		secretBytes, err := store.Get(SharedSecretKey(devices[i].DeviceID))
		if err != nil {
			if errors.Is(err, ErrSecretNotFound) {
				// No shared secret stored yet — leave empty
				continue
			}
			return nil, fmt.Errorf("load shared secret for device %s: %w", devices[i].DeviceID, err)
		}
		devices[i].SharedSecret = base64.StdEncoding.EncodeToString(secretBytes)
	}

	return devices, nil
}

// SavePairedDevices writes the paired devices list to disk.
// Shared secrets are NOT written to the JSON file (stored in SecretStore instead).
func SavePairedDevices(path string, devices []PairedDevice) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal paired devices: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write paired devices: %w", err)
	}
	return nil
}

// RemovePairedDevice removes a device by ID from the stored paired devices list
// and deletes its shared secret from the SecretStore.
func RemovePairedDevice(path string, deviceID string, store SecretStore) error {
	devices, err := LoadPairedDevices(path, store)
	if err != nil {
		return err
	}

	filtered := make([]PairedDevice, 0, len(devices))
	for _, d := range devices {
		if d.DeviceID != deviceID {
			filtered = append(filtered, d)
		}
	}

	// Delete shared secret from secure store
	if err := store.Delete(SharedSecretKey(deviceID)); err != nil {
		return fmt.Errorf("delete shared secret for device %s: %w", deviceID, err)
	}

	return SavePairedDevices(path, filtered)
}

// LoadPairedDevice returns the single paired device, or nil if none.
func LoadPairedDevice(path string, store SecretStore) (*PairedDevice, error) {
	devices, err := LoadPairedDevices(path, store)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, nil
	}
	return &devices[0], nil
}

// UpdatePairedDeviceName updates the name of a paired device if it matches
// the given device ID and the name has actually changed.
// Returns true if the name was updated, false otherwise.
func UpdatePairedDeviceName(path string, store SecretStore, deviceID, name string) (bool, error) {
	device, err := LoadPairedDevice(path, store)
	if err != nil {
		return false, fmt.Errorf("load paired device: %w", err)
	}
	if device == nil || device.DeviceID != deviceID {
		return false, nil
	}
	if device.Name == name {
		return false, nil
	}
	device.Name = name
	if err := SavePairedDevices(path, []PairedDevice{*device}); err != nil {
		return false, fmt.Errorf("save paired devices: %w", err)
	}
	return true, nil
}

// AddPairedDevice stores a paired device, replacing any existing pairing.
// The shared secret is stored in the SecretStore; metadata is written to the JSON file.
// Single-pairing mode: only one device can be paired at a time.
func AddPairedDevice(path string, device PairedDevice, store SecretStore) error {
	// Validate device ID format (defense-in-depth)
	if err := ValidateDeviceID(device.DeviceID); err != nil {
		return fmt.Errorf("add paired device: %w", err)
	}

	// Store shared secret in the secure store
	if device.SharedSecret != "" {
		secretBytes, err := base64.StdEncoding.DecodeString(device.SharedSecret)
		if err != nil {
			return fmt.Errorf("decode shared secret: %w", err)
		}
		if err := store.Set(SharedSecretKey(device.DeviceID), secretBytes); err != nil {
			return fmt.Errorf("store shared secret: %w", err)
		}
	}

	// Single-pairing: always replace the entire list with just this device
	return SavePairedDevices(path, []PairedDevice{device})
}
