package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
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

func TestRemoveKeyFiles(t *testing.T) {
	t.Run("removes pmux files and empty dir", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "keys")
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := GenerateIdentity(dir, NewMemorySecretStore()); err != nil {
			t.Fatal(err)
		}
		if err := RemoveKeyFiles(dir); err != nil {
			t.Fatalf("RemoveKeyFiles() error: %v", err)
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("empty keys dir should be removed, stat err: %v", err)
		}
	})
	t.Run("keeps foreign files", func(t *testing.T) {
		// key_path is user-configurable and may point at e.g. $HOME.
		dir := t.TempDir()
		foreign := filepath.Join(dir, "notes.txt")
		for _, f := range []string{filepath.Join(dir, secretsFileName), foreign} {
			if err := os.WriteFile(f, []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := RemoveKeyFiles(dir); err != nil {
			t.Fatalf("RemoveKeyFiles() error: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, secretsFileName)); !os.IsNotExist(err) {
			t.Errorf("%s should be removed, stat err: %v", secretsFileName, err)
		}
		if _, err := os.Stat(foreign); err != nil {
			t.Errorf("foreign file must survive: %v", err)
		}
	})
	t.Run("remove failure", func(t *testing.T) {
		dir := t.TempDir()
		// A non-empty directory in place of a key file makes os.Remove fail.
		if err := os.MkdirAll(filepath.Join(dir, publicKeyFile, "child"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := RemoveKeyFiles(dir); err == nil {
			t.Error("RemoveKeyFiles() error = nil, want failure")
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

// getErrStore is a SecretStore whose Get always fails with err and counts calls.
type getErrStore struct {
	SecretStore
	err   error
	calls int
}

func (s *getErrStore) Get(string) ([]byte, error) { s.calls++; return nil, s.err }

func TestCheckIdentity(t *testing.T) {
	storeErr := errors.New("keychain locked")
	writePub := func(dir string) {
		os.WriteFile(filepath.Join(dir, publicKeyFile), make([]byte, ed25519.PublicKeySize), keyFilePerms)
	}

	t.Run("no public key: ErrNoIdentity without touching the store", func(t *testing.T) {
		store := &getErrStore{err: storeErr}
		if err := CheckIdentity(t.TempDir(), store); !errors.Is(err, ErrNoIdentity) {
			t.Errorf("CheckIdentity() = %v, want ErrNoIdentity", err)
		}
		if store.calls != 0 {
			t.Errorf("store.Get called %d times, want 0", store.calls)
		}
	})

	t.Run("private key missing: ErrNoIdentity", func(t *testing.T) {
		dir := t.TempDir()
		writePub(dir)
		if err := CheckIdentity(dir, NewMemorySecretStore()); !errors.Is(err, ErrNoIdentity) {
			t.Errorf("CheckIdentity() = %v, want ErrNoIdentity", err)
		}
	})

	t.Run("store failure: wrapped store error, read once", func(t *testing.T) {
		dir := t.TempDir()
		writePub(dir)
		store := &getErrStore{err: storeErr}
		err := CheckIdentity(dir, store)
		if !errors.Is(err, storeErr) || errors.Is(err, ErrNoIdentity) {
			t.Errorf("CheckIdentity() = %v, want the store error", err)
		}
		if store.calls != 1 {
			t.Errorf("store.Get called %d times, want 1", store.calls)
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
	const origin = "https://signal.pmux.io"
	sig := id.SignChallenge(origin, deviceID, nonce)

	t.Run("returns base64-encoded signature", func(t *testing.T) {
		sigBytes, err := base64.StdEncoding.DecodeString(sig)
		if err != nil {
			t.Fatalf("base64 decode error: %v", err)
		}
		if len(sigBytes) != ed25519.SignatureSize {
			t.Errorf("signature size = %d, want %d", len(sigBytes), ed25519.SignatureSize)
		}
	})

	t.Run("signature verifies with public key over origin-bound message", func(t *testing.T) {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig)
		message := []byte("pocketmux-auth-v1|" + origin + "|" + deviceID + "|" + nonce)
		if !ed25519.Verify(id.Ed25519PublicKey, message, sigBytes) {
			t.Error("signature verification failed")
		}
	})

	t.Run("signature fails with wrong message", func(t *testing.T) {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig)
		wrongMessage := []byte("pocketmux-auth-v1|" + origin + "|wrong-device-id|" + nonce)
		if ed25519.Verify(id.Ed25519PublicKey, wrongMessage, sigBytes) {
			t.Error("signature should not verify with wrong message")
		}
	})

	t.Run("legacy deviceID|nonce form does not verify", func(t *testing.T) {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig)
		if ed25519.Verify(id.Ed25519PublicKey, []byte(deviceID+"|"+nonce), sigBytes) {
			t.Error("signature must not verify over the legacy message")
		}
	})

	t.Run("signature for origin A does not verify for origin B", func(t *testing.T) {
		sigBytes, _ := base64.StdEncoding.DecodeString(sig)
		other := []byte("pocketmux-auth-v1|https://evil.example|" + deviceID + "|" + nonce)
		if ed25519.Verify(id.Ed25519PublicKey, other, sigBytes) {
			t.Error("signature should not verify for a different origin")
		}
		if id.SignChallenge("https://evil.example", deviceID, nonce) == sig {
			t.Error("different origins should produce different signatures")
		}
	})

	t.Run("different nonces produce different signatures", func(t *testing.T) {
		sig2 := id.SignChallenge(origin, deviceID, "differentnonce")
		if sig == sig2 {
			t.Error("different nonces should produce different signatures")
		}
	})
}

func TestCanonicalOrigin(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"trailing slash", "https://signal.pmux.io/", "https://signal.pmux.io", false},
		{"uppercase scheme and host", "HTTPS://Signal.PMUX.io", "https://signal.pmux.io", false},
		{"default https port", "https://signal.pmux.io:443", "https://signal.pmux.io", false},
		{"explicit port ip", "http://192.168.1.5:8787", "http://192.168.1.5:8787", false},
		{"default http port with path", "http://localhost:80/v1", "http://localhost", false},
		{"non-default port with path", "https://example.com:8443/path", "https://example.com:8443", false},
		{"ipv6 with port", "http://[FD00::1]:8787", "http://[fd00::1]:8787", false},
		{"ipv6 default port", "https://[FD00::1]:443/", "https://[fd00::1]", false},
		{"ipv6 no port", "https://[FD00::1]", "https://[fd00::1]", false},
		{"query and fragment dropped", "https://example.com/a?b=c#d", "https://example.com", false},
		{"idn host", "https://Bücher.example/", "https://xn--bcher-kva.example", false},
		{"idn host with port", "https://bücher.example:8443", "https://xn--bcher-kva.example:8443", false},
		{"idn host with leading hyphen", "https://-bücher.example", "https://xn---bcher-4ya.example", false},
		{"ipv6 compressed", "http://[2001:0db8:0000:0000:0000:0000:0000:0001]:8787", "http://[2001:db8::1]:8787", false},
		{"ipv6 loopback expanded", "http://[0:0:0:0:0:0:0:1]", "http://[::1]", false},
		{"ipv4-mapped ipv6", "http://[::ffff:1.2.3.4]", "http://[::ffff:102:304]", false},
		{"port leading zeros default", "https://example.com:0443", "https://example.com", false},
		{"port leading zeros non-default", "http://example.com:08787", "http://example.com:8787", false},
		{"port out of range", "https://example.com:70000", "", true},
		{"ipv6 zone rejected", "http://[fe80::1%25eth0]", "", true},
		{"userinfo rejected", "https://user@signal.pmux.io", "", true},
		{"unparsable url", "http://[::1", "", true},
		{"missing scheme", "signal.pmux.io", "", true},
		{"empty host", "https://", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalOrigin(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("canonicalOrigin(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("canonicalOrigin(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
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
