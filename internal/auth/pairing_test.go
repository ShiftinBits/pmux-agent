package auth

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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

func TestComputeSharedSecret(t *testing.T) {
	alice, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair() alice error: %v", err)
	}
	bob, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("GenerateX25519Keypair() bob error: %v", err)
	}

	t.Run("both sides compute same shared secret", func(t *testing.T) {
		aliceSecret, err := alice.ComputeSharedSecret(bob.PublicKeyBase64())
		if err != nil {
			t.Fatalf("alice.ComputeSharedSecret() error: %v", err)
		}
		bobSecret, err := bob.ComputeSharedSecret(alice.PublicKeyBase64())
		if err != nil {
			t.Fatalf("bob.ComputeSharedSecret() error: %v", err)
		}
		if aliceSecret != bobSecret {
			t.Error("shared secrets do not match")
		}
	})

	t.Run("shared secret is 32 bytes base64", func(t *testing.T) {
		secret, err := alice.ComputeSharedSecret(bob.PublicKeyBase64())
		if err != nil {
			t.Fatalf("ComputeSharedSecret() error: %v", err)
		}
		decoded, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			t.Fatalf("base64 decode error: %v", err)
		}
		if len(decoded) != 32 {
			t.Errorf("shared secret size = %d, want 32", len(decoded))
		}
	})

	t.Run("rejects invalid base64", func(t *testing.T) {
		_, err := alice.ComputeSharedSecret("not-valid-base64!!!")
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("rejects wrong key size", func(t *testing.T) {
		wrongKey := base64.StdEncoding.EncodeToString([]byte("too-short"))
		_, err := alice.ComputeSharedSecret(wrongKey)
		if err == nil {
			t.Error("expected error for wrong key size")
		}
	})
}

func TestBuildQRPayload(t *testing.T) {
	t.Run("produces pipe-delimited format", func(t *testing.T) {
		payload, err := BuildQRPayload("ABC123", "x25519pubkey==", "device-abc", "http://localhost:8787")
		if err != nil {
			t.Fatalf("BuildQRPayload() error: %v", err)
		}
		want := "ABC123|x25519pubkey==|device-abc|http://localhost:8787"
		if payload != want {
			t.Errorf("payload = %q, want %q", payload, want)
		}
	})

	t.Run("omits default server URL", func(t *testing.T) {
		payload, err := BuildQRPayload("ABC123", "x25519pubkey==", "device-abc", "https://signal.pmux.io")
		if err != nil {
			t.Fatalf("BuildQRPayload() error: %v", err)
		}
		want := "ABC123|x25519pubkey==|device-abc"
		if payload != want {
			t.Errorf("payload = %q, want %q", payload, want)
		}
	})
}

func TestPairedDeviceStorage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")

	t.Run("load returns nil for missing file", func(t *testing.T) {
		devices, err := LoadPairedDevices(path)
		if err != nil {
			t.Fatalf("LoadPairedDevices() error: %v", err)
		}
		if devices != nil {
			t.Errorf("expected nil, got %v", devices)
		}
	})

	t.Run("save and load round-trips", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		devices := []PairedDevice{
			{DeviceID: "mobile-1", SharedSecret: "secret1==", PairedAt: now},
			{DeviceID: "mobile-2", SharedSecret: "secret2==", PairedAt: now},
		}

		if err := SavePairedDevices(path, devices); err != nil {
			t.Fatalf("SavePairedDevices() error: %v", err)
		}

		loaded, err := LoadPairedDevices(path)
		if err != nil {
			t.Fatalf("LoadPairedDevices() error: %v", err)
		}

		if len(loaded) != 2 {
			t.Fatalf("loaded %d devices, want 2", len(loaded))
		}
		if loaded[0].DeviceID != "mobile-1" {
			t.Errorf("loaded[0].DeviceID = %q, want %q", loaded[0].DeviceID, "mobile-1")
		}
		if loaded[1].SharedSecret != "secret2==" {
			t.Errorf("loaded[1].SharedSecret = %q, want %q", loaded[1].SharedSecret, "secret2==")
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

	t.Run("adds first device", func(t *testing.T) {
		err := AddPairedDevice(path, PairedDevice{
			DeviceID:     "mobile-1",
			SharedSecret: "secret1==",
			PairedAt:     time.Now(),
		})
		if err != nil {
			t.Fatalf("AddPairedDevice() error: %v", err)
		}

		devices, _ := LoadPairedDevices(path)
		if len(devices) != 1 {
			t.Fatalf("expected 1 device, got %d", len(devices))
		}
		if devices[0].DeviceID != "mobile-1" {
			t.Errorf("DeviceID = %q, want %q", devices[0].DeviceID, "mobile-1")
		}
	})

	t.Run("re-pairing replaces existing device", func(t *testing.T) {
		err := AddPairedDevice(path, PairedDevice{
			DeviceID:     "mobile-1",
			SharedSecret: "new-secret==",
			PairedAt:     time.Now(),
		})
		if err != nil {
			t.Fatalf("AddPairedDevice() error: %v", err)
		}

		devices, _ := LoadPairedDevices(path)
		if len(devices) != 1 {
			t.Fatalf("expected 1 device, got %d", len(devices))
		}
		if devices[0].SharedSecret != "new-secret==" {
			t.Errorf("SharedSecret = %q, want %q", devices[0].SharedSecret, "new-secret==")
		}
	})
}

func TestAddPairedDevice_ReplacesAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")

	// Add device A
	err := AddPairedDevice(path, PairedDevice{
		DeviceID:     "device-A",
		SharedSecret: "secretA==",
		PairedAt:     time.Now(),
	})
	if err != nil {
		t.Fatalf("AddPairedDevice(A) error: %v", err)
	}

	devices, _ := LoadPairedDevices(path)
	if len(devices) != 1 || devices[0].DeviceID != "device-A" {
		t.Fatalf("after adding A: expected [device-A], got %v", devices)
	}

	// Add device B — should replace A entirely
	err = AddPairedDevice(path, PairedDevice{
		DeviceID:     "device-B",
		SharedSecret: "secretB==",
		PairedAt:     time.Now(),
	})
	if err != nil {
		t.Fatalf("AddPairedDevice(B) error: %v", err)
	}

	devices, _ = LoadPairedDevices(path)
	if len(devices) != 1 {
		t.Fatalf("expected exactly 1 device after replacing, got %d", len(devices))
	}
	if devices[0].DeviceID != "device-B" {
		t.Errorf("DeviceID = %q, want %q", devices[0].DeviceID, "device-B")
	}
	if devices[0].SharedSecret != "secretB==" {
		t.Errorf("SharedSecret = %q, want %q", devices[0].SharedSecret, "secretB==")
	}
}

func TestLoadPairedDevice_Singular(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")

	t.Run("returns nil for missing file", func(t *testing.T) {
		device, err := LoadPairedDevice(path)
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
		device, err := LoadPairedDevice(path)
		if err != nil {
			t.Fatalf("LoadPairedDevice() error: %v", err)
		}
		if device != nil {
			t.Errorf("expected nil for empty list, got %v", device)
		}
	})

	t.Run("returns single device", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)
		if err := SavePairedDevices(path, []PairedDevice{
			{DeviceID: "mobile-1", SharedSecret: "secret==", PairedAt: now},
		}); err != nil {
			t.Fatalf("SavePairedDevices() error: %v", err)
		}

		device, err := LoadPairedDevice(path)
		if err != nil {
			t.Fatalf("LoadPairedDevice() error: %v", err)
		}
		if device == nil {
			t.Fatal("expected non-nil device")
		}
		if device.DeviceID != "mobile-1" {
			t.Errorf("DeviceID = %q, want %q", device.DeviceID, "mobile-1")
		}
		if device.SharedSecret != "secret==" {
			t.Errorf("SharedSecret = %q, want %q", device.SharedSecret, "secret==")
		}
	})
}
