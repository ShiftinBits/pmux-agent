package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()

	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	t.Run("creates valid keypair", func(t *testing.T) {
		if len(id.PrivateKey) != ed25519.PrivateKeySize {
			t.Errorf("private key size = %d, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
		}
		if len(id.Ed25519PublicKey) != ed25519.PublicKeySize {
			t.Errorf("public key size = %d, want %d", len(id.Ed25519PublicKey), ed25519.PublicKeySize)
		}
	})

	t.Run("derives device ID from public key", func(t *testing.T) {
		hash := sha256.Sum256(id.Ed25519PublicKey)
		expected := hex.EncodeToString(hash[:16])
		if id.DeviceID != expected {
			t.Errorf("DeviceID = %q, want %q", id.DeviceID, expected)
		}
		if len(id.DeviceID) != 32 {
			t.Errorf("DeviceID length = %d, want 32", len(id.DeviceID))
		}
	})

	t.Run("stores private key in SecretStore", func(t *testing.T) {
		privBytes, err := store.Get(SecretKeyEd25519Private)
		if err != nil {
			t.Fatalf("store.Get(private key) error: %v", err)
		}
		if len(privBytes) != ed25519.PrivateKeySize {
			t.Errorf("stored private key size = %d, want %d", len(privBytes), ed25519.PrivateKeySize)
		}
	})

	t.Run("writes public key file to disk", func(t *testing.T) {
		pubPath := filepath.Join(keysDir, publicKeyFile)

		pubInfo, err := os.Stat(pubPath)
		if err != nil {
			t.Fatalf("public key file not found: %v", err)
		}

		if pubInfo.Mode().Perm() != keyFilePerms {
			t.Errorf("public key permissions = %o, want %o", pubInfo.Mode().Perm(), keyFilePerms)
		}
	})

	t.Run("does not write private key to disk", func(t *testing.T) {
		// The old privateKeyFile ("ed25519.key") should NOT exist
		privPath := filepath.Join(keysDir, "ed25519.key")
		if _, err := os.Stat(privPath); !os.IsNotExist(err) {
			t.Error("private key file should NOT exist on disk")
		}
	})
}

func TestLoadIdentity(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()

	original, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	loaded, err := LoadIdentity(keysDir, store, slog.Default())
	if err != nil {
		t.Fatalf("LoadIdentity() error: %v", err)
	}

	t.Run("loaded keys match original", func(t *testing.T) {
		if !original.PrivateKey.Equal(loaded.PrivateKey) {
			t.Error("loaded private key does not match original")
		}
		if !original.Ed25519PublicKey.Equal(loaded.Ed25519PublicKey) {
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
		setup   func(dir string, store *MemorySecretStore)
		wantErr string
	}{
		{
			name:    "missing public key",
			setup:   func(dir string, store *MemorySecretStore) {},
			wantErr: "enforce public key permissions",
		},
		{
			name: "missing private key in store",
			setup: func(dir string, store *MemorySecretStore) {
				os.WriteFile(filepath.Join(dir, publicKeyFile), make([]byte, ed25519.PublicKeySize), keyFilePerms)
			},
			wantErr: "load private key from",
		},
		{
			name: "invalid private key size",
			setup: func(dir string, store *MemorySecretStore) {
				store.Set(SecretKeyEd25519Private, []byte("short"))
				os.WriteFile(filepath.Join(dir, publicKeyFile), make([]byte, ed25519.PublicKeySize), keyFilePerms)
			},
			wantErr: "invalid private key size",
		},
		{
			name: "invalid public key size",
			setup: func(dir string, store *MemorySecretStore) {
				store.Set(SecretKeyEd25519Private, make([]byte, ed25519.PrivateKeySize))
				os.WriteFile(filepath.Join(dir, publicKeyFile), []byte("short"), keyFilePerms)
			},
			wantErr: "invalid public key size",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			store := NewMemorySecretStore()
			tt.setup(dir, store)

			_, err := LoadIdentity(dir, store, slog.Default())
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !containsSubstring(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// containsSubstring is a helper for substring matching.
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestHasIdentity(t *testing.T) {
	t.Run("returns false for empty directory", func(t *testing.T) {
		dir := t.TempDir()
		store := NewMemorySecretStore()
		if HasIdentity(dir, store) {
			t.Error("HasIdentity() = true, want false")
		}
	})

	t.Run("returns false when only public key exists on disk", func(t *testing.T) {
		dir := t.TempDir()
		store := NewMemorySecretStore()
		os.WriteFile(filepath.Join(dir, publicKeyFile), make([]byte, ed25519.PublicKeySize), keyFilePerms)
		if HasIdentity(dir, store) {
			t.Error("HasIdentity() = true, want false (no private key in store)")
		}
	})

	t.Run("returns true after generation", func(t *testing.T) {
		dir := t.TempDir()
		store := NewMemorySecretStore()
		if _, err := GenerateIdentity(dir, store); err != nil {
			t.Fatalf("GenerateIdentity() error: %v", err)
		}
		if !HasIdentity(dir, store) {
			t.Error("HasIdentity() = false, want true")
		}
	})
}

func TestSignChallenge(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	deviceID := id.DeviceID
	nonce := "abc123nonce"
	sig := id.SignChallenge(deviceID, nonce)

	t.Run("returns base64-encoded signature", func(t *testing.T) {
		sigBytes, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			t.Fatalf("base64 decode error: %v", err)
		}
		if len(sigBytes) != ed25519.SignatureSize {
			t.Errorf("signature size = %d, want %d", len(sigBytes), ed25519.SignatureSize)
		}
	})

	t.Run("signature verifies with public key over deviceID|nonce", func(t *testing.T) {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig)
		message := []byte(deviceID + "|" + nonce)
		if !ed25519.Verify(id.Ed25519PublicKey, message, sigBytes) {
			t.Error("signature verification failed")
		}
	})

	t.Run("signature fails with wrong message", func(t *testing.T) {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig)
		wrongMessage := []byte("wrong-device-id" + "|" + nonce)
		if ed25519.Verify(id.Ed25519PublicKey, wrongMessage, sigBytes) {
			t.Error("signature should not verify with wrong message")
		}
	})

	t.Run("different nonces produce different signatures", func(t *testing.T) {
		sig2 := id.SignChallenge(deviceID, "differentnonce")
		if sig == sig2 {
			t.Error("different nonces should produce different signatures")
		}
	})
}

func TestEd25519PublicKeyBase64(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	b64 := id.Ed25519PublicKeyBase64()
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}

	if len(decoded) != ed25519.PublicKeySize {
		t.Errorf("decoded key size = %d, want %d", len(decoded), ed25519.PublicKeySize)
	}

	pubKey := ed25519.PublicKey(decoded)
	if !pubKey.Equal(id.Ed25519PublicKey) {
		t.Error("decoded public key does not match original")
	}
}

func TestLoadIdentity_FixesInsecurePermissions(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()

	// Generate identity
	_, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	pubPath := filepath.Join(keysDir, publicKeyFile)

	t.Run("initial permissions are 0600", func(t *testing.T) {
		pubInfo, _ := os.Stat(pubPath)
		if pubInfo.Mode().Perm() != 0600 {
			t.Errorf("public key permissions = %o, want 0600", pubInfo.Mode().Perm())
		}
	})

	t.Run("fixes insecure public key permissions on load", func(t *testing.T) {
		// Make public key world-readable
		if err := os.Chmod(pubPath, 0644); err != nil {
			t.Fatalf("chmod error: %v", err)
		}

		// Verify it was changed
		info, _ := os.Stat(pubPath)
		if info.Mode().Perm() != 0644 {
			t.Fatalf("chmod did not take effect")
		}

		// LoadIdentity should fix it
		_, err := LoadIdentity(keysDir, store, slog.Default())
		if err != nil {
			t.Fatalf("LoadIdentity() error: %v", err)
		}

		// Verify permissions were fixed back to 0600
		info, _ = os.Stat(pubPath)
		if info.Mode().Perm() != 0600 {
			t.Errorf("public key permissions after load = %o, want 0600", info.Mode().Perm())
		}
	})
}

func TestValidateDeviceID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr string // empty means valid
	}{
		{name: "valid 32-char hex", id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", wantErr: ""},
		{name: "valid all zeros", id: "00000000000000000000000000000000", wantErr: ""},
		{name: "valid all f", id: "ffffffffffffffffffffffffffffffff", wantErr: ""},
		{name: "empty string", id: "", wantErr: "must be 32 hex characters, got 0 chars"},
		{name: "too short", id: "a1b2c3", wantErr: "must be 32 hex characters, got 6 chars"},
		{name: "too long", id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4ff", wantErr: "must be 32 hex characters, got 34 chars"},
		{name: "uppercase hex", id: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4", wantErr: "contains non-hex characters"},
		{name: "mixed case", id: "a1B2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", wantErr: "contains non-hex characters"},
		{name: "non-hex chars", id: "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4", wantErr: "contains non-hex characters"},
		{name: "special chars", id: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3!!", wantErr: "contains non-hex characters"},
		{name: "path traversal", id: "../../etc/passwd................", wantErr: "contains non-hex characters"},
		{name: "spaces", id: "a1b2c3d4 5f6a1b2c3d4e5f6a1b2c3d4", wantErr: "contains non-hex characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDeviceID(tt.id)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("ValidateDeviceID(%q) unexpected error: %v", tt.id, err)
				}
			} else {
				if err == nil {
					t.Errorf("ValidateDeviceID(%q) = nil, want error containing %q", tt.id, tt.wantErr)
				} else if !containsSubstring(err.Error(), tt.wantErr) {
					t.Errorf("ValidateDeviceID(%q) error = %q, want substring %q", tt.id, err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestValidateDeviceID_DeriveRoundTrip(t *testing.T) {
	// A device ID produced by deriveDeviceID must always pass validation
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}
	if err := ValidateDeviceID(id.DeviceID); err != nil {
		t.Errorf("ValidateDeviceID(deriveDeviceID()) error: %v", err)
	}
}

func TestGenerateIdentity_Uniqueness(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	store1 := NewMemorySecretStore()
	store2 := NewMemorySecretStore()

	id1, err := GenerateIdentity(dir1, store1)
	if err != nil {
		t.Fatalf("GenerateIdentity() 1 error: %v", err)
	}
	id2, err := GenerateIdentity(dir2, store2)
	if err != nil {
		t.Fatalf("GenerateIdentity() 2 error: %v", err)
	}

	if id1.DeviceID == id2.DeviceID {
		t.Error("two generated identities should have different device IDs")
	}
}
