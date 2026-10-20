package auth

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/shiftinbits/pmux-agent/internal/config"
	"golang.org/x/crypto/hkdf"
)

// MaxMobileNameLen is the maximum allowed length for a mobile device name.
// This limit is enforced during both initial pairing and name-update flows.
const MaxMobileNameLen = 64

// SanitizeDisplayString removes every rune that is not printable per
// unicode.IsPrint (C0/C1 controls, DEL, format characters, newlines, tabs),
// so server-supplied text cannot inject terminal escape sequences. ASCII space
// and printable non-ASCII text are preserved.
func SanitizeDisplayString(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

// TruncateMobileName sanitizes a mobile device name with SanitizeDisplayString
// and then truncates it to MaxMobileNameLen runes. It operates on Unicode code
// points to avoid splitting multi-byte characters.
func TruncateMobileName(name string) string {
	runes := []rune(SanitizeDisplayString(name))
	if len(runes) > MaxMobileNameLen {
		return string(runes[:MaxMobileNameLen])
	}
	return string(runes)
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

// PairingSecretLen is the length of the QR-only pairing secret.
const PairingSecretLen = 16

// pairingSecretAlphabet is the 32-character alphabet for the pairing secret
// (no 0/O or 1/I). Its size being exactly 32 makes alphabet[b&31] unbiased.
const pairingSecretAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// pairMACLabel and pairingHKDFLabel are the domain-separation labels for the
// pair_complete MAC and the shared-secret HKDF info. Both must match the
// mobile app byte for byte.
const (
	pairMACLabel     = "pocketmux-pair-mac-v2"
	pairingHKDFLabel = "pocketmux-pairing-v2"
)

// GeneratePairingSecret returns a fresh PairingSecretLen-character secret
// drawn from pairingSecretAlphabet. The secret travels only in the QR code
// (or the manual pairing code) and is never sent to the signaling server or
// persisted; it authenticates the mobile's pair_complete and salts the
// shared-secret derivation, so a server that relays pairing cannot
// substitute its own X25519 key.
func GeneratePairingSecret() (string, error) {
	buf := make([]byte, PairingSecretLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate pairing secret: %w", err)
	}
	out := make([]byte, PairingSecretLen)
	for i, b := range buf {
		out[i] = pairingSecretAlphabet[b&31]
	}
	return string(out), nil
}

// FormatManualCode formats the pairing code and pairing secret for manual
// entry as PPPPPP-SSSS-SSSS-SSSS-SSSS.
func FormatManualCode(pairingCode, pairingSecret string) string {
	var sb strings.Builder
	sb.WriteString(pairingCode)
	for i := 0; i < len(pairingSecret); i += 4 {
		sb.WriteByte('-')
		sb.WriteString(pairingSecret[i:min(i+4, len(pairingSecret))])
	}
	return sb.String()
}

// pairBind builds BIND = hostX25519Pub || mobileX25519Pub ||
// ASCII(hostDeviceID) || ASCII(mobileDeviceID). Every field is fixed at 32
// bytes, so the concatenation is unambiguous.
func pairBind(hostPub, mobilePub []byte, hostDeviceID, mobileDeviceID string) ([]byte, error) {
	if len(hostPub) != 32 {
		return nil, fmt.Errorf("host X25519 public key must be 32 bytes, got %d", len(hostPub))
	}
	if len(mobilePub) != 32 {
		return nil, fmt.Errorf("mobile X25519 public key must be 32 bytes, got %d", len(mobilePub))
	}
	if err := ValidateDeviceID(hostDeviceID); err != nil {
		return nil, fmt.Errorf("host device ID: %w", err)
	}
	if err := ValidateDeviceID(mobileDeviceID); err != nil {
		return nil, fmt.Errorf("mobile device ID: %w", err)
	}
	bind := make([]byte, 0, 128)
	bind = append(bind, hostPub...)
	bind = append(bind, mobilePub...)
	bind = append(bind, hostDeviceID...)
	bind = append(bind, mobileDeviceID...)
	return bind, nil
}

// VerifyPairMAC checks the pairMac from a pair_complete message. The mobile
// computes it as HMAC-SHA256(key=ASCII(pairingSecret),
// ASCII("pocketmux-pair-mac-v2") || BIND), proving it read the secret from
// this host's QR code and binding both X25519 keys and both device IDs. A
// missing MAC is rejected: it means an outdated app or a relay that never
// saw the QR code.
func VerifyPairMAC(pairingSecret string, hostPub []byte, mobilePubB64, hostDeviceID, mobileDeviceID, pairMacB64 string) error {
	if pairingSecret == "" {
		return errors.New("verify pair MAC: empty pairing secret")
	}
	if pairMacB64 == "" {
		return errors.New("verify pair MAC: pair_complete has no pairMac")
	}
	mac, err := base64.StdEncoding.DecodeString(pairMacB64)
	if err != nil {
		return fmt.Errorf("verify pair MAC: decode pairMac: %w", err)
	}
	if len(mac) != sha256.Size {
		return fmt.Errorf("verify pair MAC: pairMac must be %d bytes, got %d", sha256.Size, len(mac))
	}
	mobilePub, err := base64.StdEncoding.DecodeString(mobilePubB64)
	if err != nil {
		return fmt.Errorf("verify pair MAC: decode mobile public key: %w", err)
	}
	bind, err := pairBind(hostPub, mobilePub, hostDeviceID, mobileDeviceID)
	if err != nil {
		return fmt.Errorf("verify pair MAC: %w", err)
	}

	h := hmac.New(sha256.New, []byte(pairingSecret))
	h.Write([]byte(pairMACLabel))
	h.Write(bind)
	if !hmac.Equal(h.Sum(nil), mac) {
		return errors.New("verify pair MAC: pairMac does not match")
	}
	return nil
}

// ComputeSharedSecret performs X25519 key exchange with the mobile's public
// key and derives the long-term shared secret. It is called only by the host,
// so the receiver's own public key is the host key in BIND.
// peerPubKeyBase64 is the base64-encoded X25519 public key from the mobile.
// Returns the base64-encoded shared secret.
func (kp *X25519Keypair) ComputeSharedSecret(peerPubKeyBase64, pairingSecret, hostDeviceID, mobileDeviceID string) (string, error) {
	if pairingSecret == "" {
		return "", errors.New("compute shared secret: empty pairing secret")
	}

	peerBytes, err := base64.StdEncoding.DecodeString(peerPubKeyBase64)
	if err != nil {
		return "", fmt.Errorf("decode peer public key: %w", err)
	}

	curve := ecdh.X25519()
	peerPub, err := curve.NewPublicKey(peerBytes)
	if err != nil {
		return "", fmt.Errorf("parse peer X25519 public key: %w", err)
	}

	bind, err := pairBind(kp.PublicKey.Bytes(), peerBytes, hostDeviceID, mobileDeviceID)
	if err != nil {
		return "", fmt.Errorf("compute shared secret: %w", err)
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
	// through a KDF before use. Salt (§3.3): the QR-only pairing secret, so a
	// relay that never saw the QR code cannot derive the same key. Info
	// (§3.2): versioned label followed by BIND, tying the key to both public
	// keys and both device IDs.
	info := append([]byte(pairingHKDFLabel), bind...)
	hkdfReader := hkdf.New(sha256.New, raw, []byte(pairingSecret), info)
	derived := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, derived); err != nil {
		return "", fmt.Errorf("derive shared secret via HKDF: %w", err)
	}

	return base64.StdEncoding.EncodeToString(derived), nil
}

// BuildQRPayload creates a pipe-delimited payload for the pairing QR code.
// Format: pairingCode|x25519PubKey|deviceId|serverUrl|pairingSecret
// All five fields are always present. serverUrl is empty when it matches the
// production default, to keep the QR code small; the mobile app falls back
// to the default when the field is empty.
func BuildQRPayload(pairingCode, x25519PubKeyBase64, hostDeviceID, serverURL, pairingSecret string) (string, error) {
	if serverURL == config.DefaultServerURL {
		serverURL = ""
	}
	return strings.Join([]string{pairingCode, x25519PubKeyBase64, hostDeviceID, serverURL, pairingSecret}, "|"), nil
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
// Uses temp-file-then-rename for crash-safe atomicity.
func SavePairedDevices(path string, devices []PairedDevice) error {
	data, err := json.MarshalIndent(devices, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal paired devices: %w", err)
	}

	// Write to temp file then rename for crash-safe atomicity.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".paired-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file for paired devices: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write paired devices temp: %w", err)
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("chmod paired devices temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close paired devices temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename paired devices: %w", err)
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
