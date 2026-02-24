package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	keysDir := t.TempDir()

	id, err := GenerateIdentity(keysDir)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	t.Run("creates valid keypair", func(t *testing.T) {
		if len(id.PrivateKey) != ed25519.PrivateKeySize {
			t.Errorf("private key size = %d, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
		}
		if len(id.PublicKey) != ed25519.PublicKeySize {
			t.Errorf("public key size = %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
		}
	})

	t.Run("derives device ID from public key", func(t *testing.T) {
		hash := sha256.Sum256(id.PublicKey)
		expected := hex.EncodeToString(hash[:16])
		if id.DeviceID != expected {
			t.Errorf("DeviceID = %q, want %q", id.DeviceID, expected)
		}
		if len(id.DeviceID) != 32 {
			t.Errorf("DeviceID length = %d, want 32", len(id.DeviceID))
		}
	})

	t.Run("writes key files to disk", func(t *testing.T) {
		privPath := filepath.Join(keysDir, privateKeyFile)
		pubPath := filepath.Join(keysDir, publicKeyFile)

		privInfo, err := os.Stat(privPath)
		if err != nil {
			t.Fatalf("private key file not found: %v", err)
		}
		pubInfo, err := os.Stat(pubPath)
		if err != nil {
			t.Fatalf("public key file not found: %v", err)
		}

		if privInfo.Mode().Perm() != keyFilePerms {
			t.Errorf("private key permissions = %o, want %o", privInfo.Mode().Perm(), keyFilePerms)
		}
		if pubInfo.Mode().Perm() != keyFilePerms {
			t.Errorf("public key permissions = %o, want %o", pubInfo.Mode().Perm(), keyFilePerms)
		}
	})
}

func TestLoadIdentity(t *testing.T) {
	keysDir := t.TempDir()

	original, err := GenerateIdentity(keysDir)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	loaded, err := LoadIdentity(keysDir)
	if err != nil {
		t.Fatalf("LoadIdentity() error: %v", err)
	}

	t.Run("loaded keys match original", func(t *testing.T) {
		if !original.PrivateKey.Equal(loaded.PrivateKey) {
			t.Error("loaded private key does not match original")
		}
		if !original.PublicKey.Equal(loaded.PublicKey) {
			t.Error("loaded public key does not match original")
		}
	})

	t.Run("loaded device ID matches original", func(t *testing.T) {
		if loaded.DeviceID != original.DeviceID {
			t.Errorf("loaded DeviceID = %q, want %q", loaded.DeviceID, original.DeviceID)
		}
	})
}

func TestLoadIdentity_Errors(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(dir string)
		wantErr string
	}{
		{
			name:    "missing private key",
			setup:   func(dir string) {},
			wantErr: "read private key",
		},
		{
			name: "missing public key",
			setup: func(dir string) {
				os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), keyFilePerms)
			},
			wantErr: "read public key",
		},
		{
			name: "invalid private key size",
			setup: func(dir string) {
				os.WriteFile(filepath.Join(dir, privateKeyFile), []byte("short"), keyFilePerms)
				os.WriteFile(filepath.Join(dir, publicKeyFile), make([]byte, ed25519.PublicKeySize), keyFilePerms)
			},
			wantErr: "invalid private key size",
		},
		{
			name: "invalid public key size",
			setup: func(dir string) {
				os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), keyFilePerms)
				os.WriteFile(filepath.Join(dir, publicKeyFile), []byte("short"), keyFilePerms)
			},
			wantErr: "invalid public key size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.setup(dir)

			_, err := LoadIdentity(dir)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestHasIdentity(t *testing.T) {
	t.Run("returns false for empty directory", func(t *testing.T) {
		dir := t.TempDir()
		if HasIdentity(dir) {
			t.Error("HasIdentity() = true, want false")
		}
	})

	t.Run("returns false when only private key exists", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, 64), keyFilePerms)
		if HasIdentity(dir) {
			t.Error("HasIdentity() = true, want false (only private key)")
		}
	})

	t.Run("returns true after generation", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := GenerateIdentity(dir); err != nil {
			t.Fatalf("GenerateIdentity() error: %v", err)
		}
		if !HasIdentity(dir) {
			t.Error("HasIdentity() = false, want true")
		}
	})
}

func TestSignChallenge(t *testing.T) {
	keysDir := t.TempDir()
	id, err := GenerateIdentity(keysDir)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	deviceID := id.DeviceID
	timestamp := "1700000000"
	sig := id.SignChallenge(deviceID, timestamp)

	t.Run("returns base64-encoded signature", func(t *testing.T) {
		sigBytes, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			t.Fatalf("base64 decode error: %v", err)
		}
		if len(sigBytes) != ed25519.SignatureSize {
			t.Errorf("signature size = %d, want %d", len(sigBytes), ed25519.SignatureSize)
		}
	})

	t.Run("signature verifies with public key", func(t *testing.T) {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig)
		message := []byte(deviceID + timestamp)
		if !ed25519.Verify(id.PublicKey, message, sigBytes) {
			t.Error("signature verification failed")
		}
	})

	t.Run("signature fails with wrong message", func(t *testing.T) {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig)
		wrongMessage := []byte("wrong-device-id" + timestamp)
		if ed25519.Verify(id.PublicKey, wrongMessage, sigBytes) {
			t.Error("signature should not verify with wrong message")
		}
	})

	t.Run("different timestamps produce different signatures", func(t *testing.T) {
		sig2 := id.SignChallenge(deviceID, "1700000001")
		if sig == sig2 {
			t.Error("different timestamps should produce different signatures")
		}
	})
}

func TestPublicKeyBase64(t *testing.T) {
	keysDir := t.TempDir()
	id, err := GenerateIdentity(keysDir)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	b64 := id.PublicKeyBase64()
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}

	if len(decoded) != ed25519.PublicKeySize {
		t.Errorf("decoded key size = %d, want %d", len(decoded), ed25519.PublicKeySize)
	}

	pubKey := ed25519.PublicKey(decoded)
	if !pubKey.Equal(id.PublicKey) {
		t.Error("decoded public key does not match original")
	}
}

func TestGenerateIdentity_Uniqueness(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	id1, err := GenerateIdentity(dir1)
	if err != nil {
		t.Fatalf("GenerateIdentity() 1 error: %v", err)
	}
	id2, err := GenerateIdentity(dir2)
	if err != nil {
		t.Fatalf("GenerateIdentity() 2 error: %v", err)
	}

	if id1.DeviceID == id2.DeviceID {
		t.Error("two generated identities should have different device IDs")
	}
}

