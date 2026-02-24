package auth

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// X25519Keypair holds an ephemeral X25519 keypair for key exchange during pairing.
type X25519Keypair struct {
	PrivateKey *ecdh.PrivateKey
	PublicKey  *ecdh.PublicKey
}

// PairedDevice stores information about a paired mobile device.
type PairedDevice struct {
	DeviceID     string    `json:"deviceId"`
	Name         string    `json:"name,omitempty"`
	SharedSecret string    `json:"sharedSecret"` // base64-encoded X25519 shared secret
	PairedAt     time.Time `json:"pairedAt"`
	// LastSeen is an int64 Unix timestamp (not time.Time) so that the zero
	// value 0 cleanly means "never seen" and omitempty suppresses it in JSON.
	// This matches the mobile side which stores lastSeen as a numeric timestamp.
	LastSeen int64 `json:"lastSeen,omitempty"`
}

// QRPayload is the JSON structure encoded in the pairing QR code.
type QRPayload struct {
	PairingCode        string `json:"pairingCode"`
	AgentX25519PubKey  string `json:"agentX25519PublicKey"`
	AgentDeviceID      string `json:"agentDeviceId"`
	ServerURL          string `json:"serverUrl"`
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

	secret, err := kp.PrivateKey.ECDH(peerPub)
	if err != nil {
		return "", fmt.Errorf("compute X25519 shared secret: %w", err)
	}

	return base64.StdEncoding.EncodeToString(secret), nil
}

// BuildQRPayload creates the JSON payload for the pairing QR code.
func BuildQRPayload(pairingCode string, x25519PubKeyBase64 string, agentDeviceID string, serverURL string) (string, error) {
	payload := QRPayload{
		PairingCode:       pairingCode,
		AgentX25519PubKey: x25519PubKeyBase64,
		AgentDeviceID:     agentDeviceID,
		ServerURL:         serverURL,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal QR payload: %w", err)
	}
	return string(data), nil
}

// LoadPairedDevices reads the paired devices list from disk.
func LoadPairedDevices(path string) ([]PairedDevice, error) {
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
	return devices, nil
}

// SavePairedDevices writes the paired devices list to disk.
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

// RemovePairedDevice removes a device by ID from the stored paired devices list.
func RemovePairedDevice(path string, deviceID string) error {
	devices, err := LoadPairedDevices(path)
	if err != nil {
		return err
	}

	filtered := make([]PairedDevice, 0, len(devices))
	for _, d := range devices {
		if d.DeviceID != deviceID {
			filtered = append(filtered, d)
		}
	}

	return SavePairedDevices(path, filtered)
}

// AddPairedDevice appends a new paired device to the stored list.
func AddPairedDevice(path string, device PairedDevice) error {
	devices, err := LoadPairedDevices(path)
	if err != nil {
		return err
	}

	// Replace if device ID already exists (re-pairing)
	found := false
	for i, d := range devices {
		if d.DeviceID == device.DeviceID {
			devices[i] = device
			found = true
			break
		}
	}
	if !found {
		devices = append(devices, device)
	}

	return SavePairedDevices(path, devices)
}
