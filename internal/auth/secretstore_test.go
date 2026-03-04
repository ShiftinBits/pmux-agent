package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMemorySecretStore(t *testing.T) {
	store := NewMemorySecretStore()

	t.Run("Get returns ErrSecretNotFound for missing key", func(t *testing.T) {
		_, err := store.Get("nonexistent")
		if !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("expected ErrSecretNotFound, got %v", err)
		}
	})

	t.Run("Set and Get round-trip", func(t *testing.T) {
		data := []byte("my-secret-data")
		if err := store.Set("key1", data); err != nil {
			t.Fatalf("Set() error: %v", err)
		}

		got, err := store.Get("key1")
		if err != nil {
			t.Fatalf("Get() error: %v", err)
		}
		if string(got) != string(data) {
			t.Errorf("Get() = %q, want %q", got, data)
		}
	})

	t.Run("Get returns a copy (not shared memory)", func(t *testing.T) {
		data := []byte("original")
		store.Set("key-copy", data)

		got, _ := store.Get("key-copy")
		got[0] = 'X' // mutate the returned copy

		got2, _ := store.Get("key-copy")
		if got2[0] == 'X' {
			t.Error("Get() returned shared memory — mutation propagated")
		}
	})

	t.Run("Set overwrites existing value", func(t *testing.T) {
		store.Set("overwrite", []byte("first"))
		store.Set("overwrite", []byte("second"))

		got, _ := store.Get("overwrite")
		if string(got) != "second" {
			t.Errorf("Get() = %q, want %q", got, "second")
		}
	})

	t.Run("Delete removes a key", func(t *testing.T) {
		store.Set("to-delete", []byte("data"))

		if err := store.Delete("to-delete"); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}

		_, err := store.Get("to-delete")
		if !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("expected ErrSecretNotFound after delete, got %v", err)
		}
	})

	t.Run("Delete non-existent key returns nil", func(t *testing.T) {
		if err := store.Delete("never-existed"); err != nil {
			t.Errorf("Delete(non-existent) error: %v", err)
		}
	})

	t.Run("Backend returns memory", func(t *testing.T) {
		if got := store.Backend(); got != "memory" {
			t.Errorf("Backend() = %q, want %q", got, "memory")
		}
	})
}

func TestFileSecretStore(t *testing.T) {
	dir := t.TempDir()
	store := NewFileSecretStore(dir)

	t.Run("Get returns ErrSecretNotFound for empty store", func(t *testing.T) {
		_, err := store.Get("nonexistent")
		if !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("expected ErrSecretNotFound, got %v", err)
		}
	})

	t.Run("Set and Get round-trip", func(t *testing.T) {
		data := []byte("encrypted-secret-data")
		if err := store.Set("file-key1", data); err != nil {
			t.Fatalf("Set() error: %v", err)
		}

		got, err := store.Get("file-key1")
		if err != nil {
			t.Fatalf("Get() error: %v", err)
		}
		if string(got) != string(data) {
			t.Errorf("Get() = %q, want %q", got, data)
		}
	})

	t.Run("persists across new store instances", func(t *testing.T) {
		data := []byte("persistent-data")
		if err := store.Set("persist-key", data); err != nil {
			t.Fatalf("Set() error: %v", err)
		}

		// Create a new store pointing at the same directory
		store2 := NewFileSecretStore(dir)
		got, err := store2.Get("persist-key")
		if err != nil {
			t.Fatalf("Get() from new store error: %v", err)
		}
		if string(got) != string(data) {
			t.Errorf("Get() = %q, want %q", got, data)
		}
	})

	t.Run("Set overwrites existing value", func(t *testing.T) {
		store.Set("overwrite", []byte("first"))
		store.Set("overwrite", []byte("second"))

		got, _ := store.Get("overwrite")
		if string(got) != "second" {
			t.Errorf("Get() = %q, want %q", got, "second")
		}
	})

	t.Run("Delete removes a key", func(t *testing.T) {
		store.Set("to-delete", []byte("data"))

		if err := store.Delete("to-delete"); err != nil {
			t.Fatalf("Delete() error: %v", err)
		}

		_, err := store.Get("to-delete")
		if !errors.Is(err, ErrSecretNotFound) {
			t.Errorf("expected ErrSecretNotFound after delete, got %v", err)
		}
	})

	t.Run("Delete non-existent key returns nil", func(t *testing.T) {
		if err := store.Delete("never-existed"); err != nil {
			t.Errorf("Delete(non-existent) error: %v", err)
		}
	})

	t.Run("Backend returns encrypted-file", func(t *testing.T) {
		if got := store.Backend(); got != "encrypted-file" {
			t.Errorf("Backend() = %q, want %q", got, "encrypted-file")
		}
	})

	t.Run("handles binary data", func(t *testing.T) {
		// Store raw binary (like an Ed25519 private key)
		binary := make([]byte, 64)
		for i := range binary {
			binary[i] = byte(i)
		}
		if err := store.Set("binary-key", binary); err != nil {
			t.Fatalf("Set() error: %v", err)
		}

		got, err := store.Get("binary-key")
		if err != nil {
			t.Fatalf("Get() error: %v", err)
		}
		if len(got) != len(binary) {
			t.Fatalf("Get() length = %d, want %d", len(got), len(binary))
		}
		for i := range binary {
			if got[i] != binary[i] {
				t.Errorf("byte[%d] = %d, want %d", i, got[i], binary[i])
				break
			}
		}
	})
}

func TestSharedSecretKey(t *testing.T) {
	got := SharedSecretKey("device-abc123")
	want := "shared-secret-device-abc123"
	if got != want {
		t.Errorf("SharedSecretKey() = %q, want %q", got, want)
	}
}

func TestNewSecretStore_FileFallback(t *testing.T) {
	dir := t.TempDir()

	// "file" backend should always succeed
	store, err := NewSecretStore(dir, "file")
	if err != nil {
		t.Fatalf("NewSecretStore(file) error: %v", err)
	}
	if store.Backend() != "encrypted-file" {
		t.Errorf("Backend() = %q, want %q", store.Backend(), "encrypted-file")
	}
}

func TestNewSecretStore_InvalidBackend(t *testing.T) {
	dir := t.TempDir()

	_, err := NewSecretStore(dir, "invalid")
	if err == nil {
		t.Fatal("expected error for invalid backend, got nil")
	}
}

func TestFallbackMachineID(t *testing.T) {
	t.Run("generates and persists a 32-byte key", func(t *testing.T) {
		dir := t.TempDir()

		id1, err := fallbackMachineID(dir)
		if err != nil {
			t.Fatalf("fallbackMachineID() error: %v", err)
		}
		if len(id1) == 0 {
			t.Fatal("fallbackMachineID() returned empty result")
		}

		// Verify the key file exists with correct size
		keyPath := filepath.Join(dir, "machine-id.key")
		data, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatalf("reading key file: %v", err)
		}
		if len(data) != 32 {
			t.Errorf("key file size = %d, want 32", len(data))
		}

		// Verify file permissions (Unix only)
		info, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("stat key file: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("key file permissions = %o, want 0600", perm)
		}
	})

	t.Run("returns same value on subsequent calls", func(t *testing.T) {
		dir := t.TempDir()

		id1, err := fallbackMachineID(dir)
		if err != nil {
			t.Fatalf("first call error: %v", err)
		}

		id2, err := fallbackMachineID(dir)
		if err != nil {
			t.Fatalf("second call error: %v", err)
		}

		if !bytes.Equal(id1, id2) {
			t.Error("fallbackMachineID() returned different values on subsequent calls")
		}
	})

	t.Run("rejects corrupt key file", func(t *testing.T) {
		dir := t.TempDir()

		// Write a key file with wrong size
		keyPath := filepath.Join(dir, "machine-id.key")
		if err := os.WriteFile(keyPath, []byte("too-short"), 0600); err != nil {
			t.Fatalf("writing corrupt key: %v", err)
		}

		_, err := fallbackMachineID(dir)
		if err == nil {
			t.Fatal("expected error for corrupt key file, got nil")
		}
	})

	t.Run("creates directory if missing", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "nested", "keys")

		_, err := fallbackMachineID(dir)
		if err != nil {
			t.Fatalf("fallbackMachineID() error: %v", err)
		}

		keyPath := filepath.Join(dir, "machine-id.key")
		if _, err := os.Stat(keyPath); err != nil {
			t.Errorf("key file not created at %s: %v", keyPath, err)
		}
	})
}
