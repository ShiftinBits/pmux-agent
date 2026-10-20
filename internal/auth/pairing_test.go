package auth

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/config"
)

func TestTruncateMobileName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty string", "", ""},
		{"short name", "My iPhone", "My iPhone"},
		{"exactly 64 chars", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"65 chars truncated to 64", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"very long name", strings.Repeat("a", 1000), strings.Repeat("a", 64)},
		{"multi-byte emoji truncation", strings.Repeat("\U0001F4F1", 65), strings.Repeat("\U0001F4F1", 64)},
		{"mixed ASCII and emoji", "Phone " + strings.Repeat("\U0001F600", 60), "Phone " + strings.Repeat("\U0001F600", 58)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateMobileName(tt.input)
			if got != tt.want {
				t.Errorf("TruncateMobileName() = %q (len %d), want %q (len %d)", got, len(got), tt.want, len(tt.want))
			}
		})
	}
}

func TestGenerateX25519Keypair(t *testing.T) {
	kp, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair() error: %v", err)
	}

	t.Run("generates valid keypair", func(t *testing.T) {
		if kp.PrivateKey == nil {
			t.Error("private key is nil")
		}
		if kp.PublicKey == nil {
			t.Error("public key is nil")
		}
	})

	t.Run("public key is 32 bytes", func(t *testing.T) {
		pubBytes := kp.PublicKey.Bytes()
		if len(pubBytes) != 32 {
			t.Errorf("public key size = %d, want 32", len(pubBytes))
		}
	})

	t.Run("base64 encodes correctly", func(t *testing.T) {
		b64 := kp.PublicKeyBase64()
		decoded, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			t.Fatalf("base64 decode error: %v", err)
		}
		if len(decoded) != 32 {
			t.Errorf("decoded key size = %d, want 32", len(decoded))
		}
	})

	t.Run("two keypairs are different", func(t *testing.T) {
		kp2, err := GenerateX25519Keypair()
		if err != nil {
			t.Fatalf("GenerateX25519Keypair() 2 error: %v", err)
		}
		if kp.PublicKeyBase64() == kp2.PublicKeyBase64() {
			t.Error("two keypairs should have different public keys")
		}
	})
}

// Pairing v2 test vector. Must match the mobile app's cross-implementation
// test byte for byte.
const (
	vecHostDeviceID   = "0123456789abcdef0123456789abcdef"
	vecMobileDeviceID = "fedcba9876543210fedcba9876543210"
	vecPairingSecret  = "ABCDEFGHJKLMNPQR"
	vecHostPub        = "e06Qm75//kTEZaIgA31gjuNYl9Me+XLwf3SJLLD3PxM="
	vecMobilePub      = "D6poTtKIZ7l/Smot7l34zpdOdrcBjj8iocTPJnhXDyA="
	vecPairMac        = "+WJq2u9YNctr2j0+n/66h36wqJP4fvuohxvPnZa+Xvk="
	vecSharedSecret   = "FaYdo9hMbk1fzjwKPJfMDpQa7VMIBrjwN1p/CaSO47Y="
)

// fixedKeypair builds an X25519 keypair from a 32-byte scalar filled with b.
func fixedKeypair(t *testing.T, b byte) *X25519Keypair {
	t.Helper()
	priv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatalf("NewPrivateKey(0x%02x): %v", b, err)
	}
	return &X25519Keypair{PrivateKey: priv, PublicKey: priv.PublicKey()}
}

func TestPairingV2_KnownVector(t *testing.T) {
	host := fixedKeypair(t, 0x11)
	mobile := fixedKeypair(t, 0x22)

	if got := host.PublicKeyBase64(); got != vecHostPub {
		t.Fatalf("host public key = %s, want %s", got, vecHostPub)
	}
	if got := mobile.PublicKeyBase64(); got != vecMobilePub {
		t.Fatalf("mobile public key = %s, want %s", got, vecMobilePub)
	}

	t.Run("pairMac verifies", func(t *testing.T) {
		err := VerifyPairMAC(vecPairingSecret, vecMobilePub, vecMobileDeviceID, vecPairMac)
		if err != nil {
			t.Errorf("VerifyPairMAC() error: %v", err)
		}
	})

	t.Run("shared secret matches", func(t *testing.T) {
		secret, err := host.ComputeSharedSecret(vecMobilePub, vecPairingSecret, vecHostDeviceID, vecMobileDeviceID)
		if err != nil {
			t.Fatalf("ComputeSharedSecret() error: %v", err)
		}
		if secret != vecSharedSecret {
			t.Errorf("shared secret = %s, want %s", secret, vecSharedSecret)
		}
	})
}

func TestComputeSharedSecret(t *testing.T) {
	host := fixedKeypair(t, 0x11)
	mobile := fixedKeypair(t, 0x22)

	tests := []struct {
		name           string
		peerPub        string
		pairingSecret  string
		hostDeviceID   string
		mobileDeviceID string
		wantErr        bool
		wantSecret     string
	}{
		{"known vector", vecMobilePub, vecPairingSecret, vecHostDeviceID, vecMobileDeviceID, false, vecSharedSecret},
		{"rejects invalid base64", "not-valid-base64!!!", vecPairingSecret, vecHostDeviceID, vecMobileDeviceID, true, ""},
		{"rejects wrong key size", base64.StdEncoding.EncodeToString([]byte("too-short")), vecPairingSecret, vecHostDeviceID, vecMobileDeviceID, true, ""},
		{"rejects empty pairing secret", vecMobilePub, "", vecHostDeviceID, vecMobileDeviceID, true, ""},
		{"rejects invalid host device ID", vecMobilePub, vecPairingSecret, "short", vecMobileDeviceID, true, ""},
		{"rejects invalid mobile device ID", vecMobilePub, vecPairingSecret, vecHostDeviceID, "short", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := host.ComputeSharedSecret(tt.peerPub, tt.pairingSecret, tt.hostDeviceID, tt.mobileDeviceID)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got secret %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ComputeSharedSecret() error: %v", err)
			}
			if got != tt.wantSecret {
				t.Errorf("secret = %s, want %s", got, tt.wantSecret)
			}
		})
	}

	t.Run("bound to pairing secret and device IDs", func(t *testing.T) {
		variants := []struct {
			name           string
			pairingSecret  string
			hostDeviceID   string
			mobileDeviceID string
		}{
			{"different secret", "ABCDEFGHJKLMNPQS", vecHostDeviceID, vecMobileDeviceID},
			{"swapped device IDs", vecPairingSecret, vecMobileDeviceID, vecHostDeviceID},
		}
		for _, v := range variants {
			got, err := host.ComputeSharedSecret(mobile.PublicKeyBase64(), v.pairingSecret, v.hostDeviceID, v.mobileDeviceID)
			if err != nil {
				t.Fatalf("%s: ComputeSharedSecret() error: %v", v.name, err)
			}
			if got == vecSharedSecret {
				t.Errorf("%s: secret should differ from the vector", v.name)
			}
		}
	})
}

func TestGeneratePairingSecret(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 64; i++ {
		secret, err := GeneratePairingSecret()
		if err != nil {
			t.Fatalf("GeneratePairingSecret() error: %v", err)
		}
		if len(secret) != PairingSecretLen {
			t.Fatalf("secret length = %d, want %d", len(secret), PairingSecretLen)
		}
		for _, c := range secret {
			if !strings.ContainsRune(pairingSecretAlphabet, c) {
				t.Fatalf("secret %q contains %q outside the alphabet", secret, c)
			}
		}
		if seen[secret] {
			t.Fatalf("duplicate secret %q", secret)
		}
		seen[secret] = true
	}

	if len(pairingSecretAlphabet) != 32 {
		t.Errorf("alphabet length = %d, want 32 (alphabet[b&31] must be unbiased)", len(pairingSecretAlphabet))
	}
}

func TestFormatManualCode(t *testing.T) {
	got := FormatManualCode("ABC234", vecPairingSecret)
	const want = "ABC234-ABCD-EFGH-JKLM-NPQR"
	if got != want {
		t.Errorf("FormatManualCode() = %q, want %q", got, want)
	}
}

// pairMacFor computes the pair_complete MAC the way the mobile app does,
// independently of VerifyPairMAC.
func pairMacFor(secret string, mobilePub []byte, mobileDeviceID string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("pocketmux-pair-mac-v2"))
	h.Write(mobilePub)
	h.Write([]byte(mobileDeviceID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func TestVerifyPairMAC(t *testing.T) {
	other := fixedKeypair(t, 0x33)
	const otherMobileDeviceID = "fedcba9876543210fedcba9876543211"

	tests := []struct {
		name           string
		pairingSecret  string
		mobilePub      string
		mobileDeviceID string
		pairMac        string
		wantErr        bool
	}{
		{"valid", vecPairingSecret, vecMobilePub, vecMobileDeviceID, vecPairMac, false},
		{"tampered mobile key", vecPairingSecret, other.PublicKeyBase64(), vecMobileDeviceID, vecPairMac, true},
		{"tampered mobile device ID", vecPairingSecret, vecMobilePub, otherMobileDeviceID, vecPairMac, true},
		{"MAC over a different mobile key", vecPairingSecret, vecMobilePub, vecMobileDeviceID, pairMacFor(vecPairingSecret, other.PublicKey.Bytes(), vecMobileDeviceID), true},
		{"MAC over a different mobile device ID", vecPairingSecret, vecMobilePub, vecMobileDeviceID, pairMacFor(vecPairingSecret, mustDecodeB64(t, vecMobilePub), otherMobileDeviceID), true},
		{"wrong secret", "ABCDEFGHJKLMNPQS", vecMobilePub, vecMobileDeviceID, vecPairMac, true},
		{"empty secret", "", vecMobilePub, vecMobileDeviceID, vecPairMac, true},
		{"missing MAC", vecPairingSecret, vecMobilePub, vecMobileDeviceID, "", true},
		{"MAC not base64", vecPairingSecret, vecMobilePub, vecMobileDeviceID, "!!!", true},
		{"MAC wrong length", vecPairingSecret, vecMobilePub, vecMobileDeviceID, base64.StdEncoding.EncodeToString(make([]byte, 16)), true},
		{"mobile key not base64", vecPairingSecret, "!!!", vecMobileDeviceID, vecPairMac, true},
		{"mobile key wrong length", vecPairingSecret, base64.StdEncoding.EncodeToString(make([]byte, 31)), vecMobileDeviceID, vecPairMac, true},
		{"mobile device ID too short", vecPairingSecret, vecMobilePub, "fedcba98", vecPairMac, true},
		{"mobile device ID uppercase hex", vecPairingSecret, vecMobilePub, "FEDCBA9876543210FEDCBA9876543210", vecPairMac, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPairMAC(tt.pairingSecret, tt.mobilePub, tt.mobileDeviceID, tt.pairMac)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPairMAC() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	t.Run("helper reproduces the vector", func(t *testing.T) {
		if got := pairMacFor(vecPairingSecret, mustDecodeB64(t, vecMobilePub), vecMobileDeviceID); got != vecPairMac {
			t.Errorf("pairMacFor() = %s, want %s", got, vecPairMac)
		}
	})
}

func mustDecodeB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode %q: %v", s, err)
	}
	return b
}

func TestBuildQRPayload(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		want      string
	}{
		{"custom server URL", "http://localhost:8787", "ABC123|x25519pubkey==|device-abc|http://localhost:8787|" + vecPairingSecret},
		{"default server URL is empty", config.DefaultServerURL, "ABC123|x25519pubkey==|device-abc||" + vecPairingSecret},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := BuildQRPayload("ABC123", "x25519pubkey==", "device-abc", tt.serverURL, vecPairingSecret)
			if err != nil {
				t.Fatalf("BuildQRPayload() error: %v", err)
			}
			if payload != tt.want {
				t.Errorf("payload = %q, want %q", payload, tt.want)
			}
			if n := len(strings.Split(payload, "|")); n != 5 {
				t.Errorf("payload has %d fields, want 5", n)
			}
		})
	}
}

func TestPairedDeviceStorage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := NewMemorySecretStore()

	t.Run("load returns nil for missing file", func(t *testing.T) {
		devices, err := LoadPairedDevices(path, store)
		if err != nil {
			t.Fatalf("LoadPairedDevices() error: %v", err)
		}
		if devices != nil {
			t.Errorf("expected nil, got %v", devices)
		}
	})

	t.Run("save and load round-trips", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		// Use valid base64 for shared secrets (base64 of "secret-data-1" and "secret-data-2")
		secret1 := base64.StdEncoding.EncodeToString([]byte("secret-data-1"))
		secret2 := base64.StdEncoding.EncodeToString([]byte("secret-data-2"))

		devices := []PairedDevice{
			{DeviceID: "aa11bb22cc33dd44ee55ff66aa11bb22", SharedSecret: secret1, PairedAt: now},
			{DeviceID: "bb22cc33dd44ee55ff66aa11bb22cc33", SharedSecret: secret2, PairedAt: now},
		}

		// Use AddPairedDevice to store secrets in store and metadata on disk
		for _, d := range devices {
			if err := AddPairedDevice(path, d, store); err != nil {
				t.Fatalf("AddPairedDevice() error: %v", err)
			}
		}

		loaded, err := LoadPairedDevices(path, store)
		if err != nil {
			t.Fatalf("LoadPairedDevices() error: %v", err)
		}

		// Single-pairing mode: only the last added device remains
		if len(loaded) != 1 {
			t.Fatalf("loaded %d devices, want 1 (single-pairing)", len(loaded))
		}
		if loaded[0].DeviceID != "bb22cc33dd44ee55ff66aa11bb22cc33" {
			t.Errorf("loaded[0].DeviceID = %q, want %q", loaded[0].DeviceID, "bb22cc33dd44ee55ff66aa11bb22cc33")
		}
		if loaded[0].SharedSecret == "" {
			t.Error("loaded[0].SharedSecret should not be empty")
		}
	})

	t.Run("shared secret not in JSON file", func(t *testing.T) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read file: %v", err)
		}
		// SharedSecret has json:"-", so it should NOT appear in the JSON
		if containsSubstring(string(data), "sharedSecret") {
			t.Error("sharedSecret should NOT appear in JSON file (stored in SecretStore)")
		}
	})

	t.Run("file permissions are 0600", func(t *testing.T) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat error: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("file permissions = %o, want %o", info.Mode().Perm(), 0600)
		}
	})
}

func TestAddPairedDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := NewMemorySecretStore()

	t.Run("adds first device", func(t *testing.T) {
		secret := base64.StdEncoding.EncodeToString([]byte("first-secret"))
		err := AddPairedDevice(path, PairedDevice{
			DeviceID:     "aa11bb22cc33dd44ee55ff66aa11bb22",
			SharedSecret: secret,
			PairedAt:     time.Now(),
		}, store)
		if err != nil {
			t.Fatalf("AddPairedDevice() error: %v", err)
		}

		devices, _ := LoadPairedDevices(path, store)
		if len(devices) != 1 {
			t.Fatalf("expected 1 device, got %d", len(devices))
		}
		if devices[0].DeviceID != "aa11bb22cc33dd44ee55ff66aa11bb22" {
			t.Errorf("DeviceID = %q, want %q", devices[0].DeviceID, "aa11bb22cc33dd44ee55ff66aa11bb22")
		}
	})

	t.Run("re-pairing replaces existing device", func(t *testing.T) {
		newSecret := base64.StdEncoding.EncodeToString([]byte("new-secret-data"))
		err := AddPairedDevice(path, PairedDevice{
			DeviceID:     "aa11bb22cc33dd44ee55ff66aa11bb22",
			SharedSecret: newSecret,
			PairedAt:     time.Now(),
		}, store)
		if err != nil {
			t.Fatalf("AddPairedDevice() error: %v", err)
		}

		devices, _ := LoadPairedDevices(path, store)
		if len(devices) != 1 {
			t.Fatalf("expected 1 device, got %d", len(devices))
		}
		// Verify the shared secret was updated in the store
		secretBytes, err := store.Get(SharedSecretKey("aa11bb22cc33dd44ee55ff66aa11bb22"))
		if err != nil {
			t.Fatalf("store.Get() error: %v", err)
		}
		gotSecret := base64.StdEncoding.EncodeToString(secretBytes)
		if gotSecret != newSecret {
			t.Errorf("SharedSecret = %q, want %q", gotSecret, newSecret)
		}
	})
}

func TestAddPairedDevice_ReplacesAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := NewMemorySecretStore()

	secretA := base64.StdEncoding.EncodeToString([]byte("secret-A-data"))
	secretB := base64.StdEncoding.EncodeToString([]byte("secret-B-data"))

	// Add device A
	err := AddPairedDevice(path, PairedDevice{
		DeviceID:     "cc33dd44ee55ff66aa11bb22cc33dd44",
		SharedSecret: secretA,
		PairedAt:     time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice(A) error: %v", err)
	}

	devices, _ := LoadPairedDevices(path, store)
	if len(devices) != 1 || devices[0].DeviceID != "cc33dd44ee55ff66aa11bb22cc33dd44" {
		t.Fatalf("after adding A: expected [device-A], got %v", devices)
	}

	// Add device B — should replace A entirely
	err = AddPairedDevice(path, PairedDevice{
		DeviceID:     "dd44ee55ff66aa11bb22cc33dd44ee55",
		SharedSecret: secretB,
		PairedAt:     time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice(B) error: %v", err)
	}

	devices, _ = LoadPairedDevices(path, store)
	if len(devices) != 1 {
		t.Fatalf("expected exactly 1 device after replacing, got %d", len(devices))
	}
	if devices[0].DeviceID != "dd44ee55ff66aa11bb22cc33dd44ee55" {
		t.Errorf("DeviceID = %q, want %q", devices[0].DeviceID, "dd44ee55ff66aa11bb22cc33dd44ee55")
	}
	// Verify shared secret is in store
	secretBytes, err := store.Get(SharedSecretKey("dd44ee55ff66aa11bb22cc33dd44ee55"))
	if err != nil {
		t.Fatalf("store.Get() error: %v", err)
	}
	gotSecret := base64.StdEncoding.EncodeToString(secretBytes)
	if gotSecret != secretB {
		t.Errorf("SharedSecret = %q, want %q", gotSecret, secretB)
	}
}

func TestLoadPairedDevice_Singular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := NewMemorySecretStore()

	t.Run("returns nil for missing file", func(t *testing.T) {
		device, err := LoadPairedDevice(path, store)
		if err != nil {
			t.Fatalf("LoadPairedDevice() error: %v", err)
		}
		if device != nil {
			t.Errorf("expected nil, got %v", device)
		}
	})

	t.Run("returns nil for empty list", func(t *testing.T) {
		if err := SavePairedDevices(path, []PairedDevice{}); err != nil {
			t.Fatalf("SavePairedDevices() error: %v", err)
		}
		device, err := LoadPairedDevice(path, store)
		if err != nil {
			t.Fatalf("LoadPairedDevice() error: %v", err)
		}
		if device != nil {
			t.Errorf("expected nil for empty list, got %v", device)
		}
	})

	t.Run("returns single device with secret from store", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		secret := base64.StdEncoding.EncodeToString([]byte("device-secret"))

		// Add device via AddPairedDevice to store secret properly
		err := AddPairedDevice(path, PairedDevice{
			DeviceID:     "aa11bb22cc33dd44ee55ff66aa11bb22",
			SharedSecret: secret,
			PairedAt:     now,
		}, store)
		if err != nil {
			t.Fatalf("AddPairedDevice() error: %v", err)
		}

		device, err := LoadPairedDevice(path, store)
		if err != nil {
			t.Fatalf("LoadPairedDevice() error: %v", err)
		}
		if device == nil {
			t.Fatal("expected non-nil device")
		}
		if device.DeviceID != "aa11bb22cc33dd44ee55ff66aa11bb22" {
			t.Errorf("DeviceID = %q, want %q", device.DeviceID, "aa11bb22cc33dd44ee55ff66aa11bb22")
		}
		if device.SharedSecret == "" {
			t.Error("SharedSecret should not be empty (loaded from store)")
		}
	})
}

func TestUpdatePairedDeviceName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := NewMemorySecretStore()

	// Set up a paired device with a name
	secret := base64.StdEncoding.EncodeToString([]byte("test-secret"))
	err := AddPairedDevice(path, PairedDevice{
		DeviceID:     "aa11bb22cc33dd44ee55ff66aa11bb22",
		Name:         "Old Phone",
		SharedSecret: secret,
		PairedAt:     time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice() error: %v", err)
	}

	t.Run("updates matching device", func(t *testing.T) {
		updated, err := UpdatePairedDeviceName(path, store, "aa11bb22cc33dd44ee55ff66aa11bb22", "New Phone")
		if err != nil {
			t.Fatalf("UpdatePairedDeviceName() error: %v", err)
		}
		if !updated {
			t.Error("expected updated=true, got false")
		}

		// Reload and verify name changed
		device, err := LoadPairedDevice(path, store)
		if err != nil {
			t.Fatalf("LoadPairedDevice() error: %v", err)
		}
		if device.Name != "New Phone" {
			t.Errorf("Name = %q, want %q", device.Name, "New Phone")
		}
	})

	t.Run("ignores non-matching device", func(t *testing.T) {
		updated, err := UpdatePairedDeviceName(path, store, "wrong-device-id", "Should Not Apply")
		if err != nil {
			t.Fatalf("UpdatePairedDeviceName() error: %v", err)
		}
		if updated {
			t.Error("expected updated=false for non-matching device ID")
		}

		// Verify name unchanged
		device, err := LoadPairedDevice(path, store)
		if err != nil {
			t.Fatalf("LoadPairedDevice() error: %v", err)
		}
		if device.Name != "New Phone" {
			t.Errorf("Name = %q, want %q (should be unchanged)", device.Name, "New Phone")
		}
	})

	t.Run("no-ops when name unchanged", func(t *testing.T) {
		updated, err := UpdatePairedDeviceName(path, store, "aa11bb22cc33dd44ee55ff66aa11bb22", "New Phone")
		if err != nil {
			t.Fatalf("UpdatePairedDeviceName() error: %v", err)
		}
		if updated {
			t.Error("expected updated=false when name is the same")
		}
	})
}

func TestRemovePairedDevice_DeletesSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := NewMemorySecretStore()

	err := AddPairedDevice(path, PairedDevice{
		DeviceID:     "aa11bb22cc33dd44ee55ff66aa11bb22",
		SharedSecret: base64.StdEncoding.EncodeToString([]byte("test-secret-value")),
		PairedAt:     time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice() error: %v", err)
	}

	// Verify secret exists
	_, err = store.Get(SharedSecretKey("aa11bb22cc33dd44ee55ff66aa11bb22"))
	if err != nil {
		t.Fatalf("secret should exist before removal: %v", err)
	}

	// Remove the device
	err = RemovePairedDevice(path, "aa11bb22cc33dd44ee55ff66aa11bb22", store)
	if err != nil {
		t.Fatalf("RemovePairedDevice() error: %v", err)
	}

	// Verify secret is deleted
	_, err = store.Get(SharedSecretKey("aa11bb22cc33dd44ee55ff66aa11bb22"))
	if err == nil {
		t.Error("expected error after secret deletion, got nil")
	}

	// Verify device list is empty
	devices, _ := LoadPairedDevices(path, store)
	if len(devices) != 0 {
		t.Errorf("expected 0 devices after removal, got %d", len(devices))
	}
}

func TestSanitizeDisplayString(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"csi", "a\x1b[2K\rb", "a[2Kb"},
		{"osc52", "a\x1b]52;c;ZXZpbA==\x07b", "a]52;c;ZXZpbA==b"},
		{"bel", "a\x07b", "ab"},
		{"del", "a\x7fb", "ab"},
		{"c1 csi", "a\u009bb", "ab"},
		{"newline and tab", "a\nb\tc", "abc"},
		{"emoji and curly apostrophe", "Bob’s iPhone 📱", "Bob’s iPhone 📱"},
		{"non-latin", "電話 Телефон", "電話 Телефон"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SanitizeDisplayString(tt.in); got != tt.want {
				t.Errorf("SanitizeDisplayString(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTruncateMobileName_SanitizesBeforeTruncating(t *testing.T) {
	in := strings.Repeat("\x1b", 100) + strings.Repeat("a", MaxMobileNameLen+5)
	got := TruncateMobileName(in)
	if want := strings.Repeat("a", MaxMobileNameLen); got != want {
		t.Errorf("TruncateMobileName = %q, want %d 'a' runes", got, MaxMobileNameLen)
	}
}
