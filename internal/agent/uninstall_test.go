package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

func testUninstallPaths(dir string) config.Paths {
	return config.Paths{
		ConfigDir:     dir,
		KeysDir:       filepath.Join(dir, "keys"),
		PairedDevices: filepath.Join(dir, "paired_devices.json"),
		ConfigFile:    filepath.Join(dir, "config.toml"),
	}
}

func TestRunUninstall_UserCancels(t *testing.T) {
	dir := t.TempDir()
	paths := testUninstallPaths(dir)
	store := auth.NewMemorySecretStore()
	mgr := &mockServiceManager{}

	var buf bytes.Buffer
	err := RunUninstall(paths, store, mgr, false, "", strings.NewReader("n\n"), &buf)
	if err != nil {
		t.Fatalf("RunUninstall: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Cancelled.") {
		t.Errorf("expected 'Cancelled.' in output, got: %s", output)
	}

	// Config dir should still exist
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("config directory should not have been removed")
	}
}

func TestRunUninstall_EOF(t *testing.T) {
	dir := t.TempDir()
	paths := testUninstallPaths(dir)
	store := auth.NewMemorySecretStore()
	mgr := &mockServiceManager{}

	var buf bytes.Buffer
	err := RunUninstall(paths, store, mgr, false, "", strings.NewReader(""), &buf)
	if err != nil {
		t.Fatalf("RunUninstall: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Cancelled.") {
		t.Errorf("expected 'Cancelled.' on EOF, got: %s", output)
	}
}

func TestRunUninstall_FullUninstall(t *testing.T) {
	dir := t.TempDir()
	paths := testUninstallPaths(dir)

	// Create keys dir and config file so the directory has content
	if err := os.MkdirAll(paths.KeysDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ConfigFile, []byte("name = \"test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	store := auth.NewMemorySecretStore()
	// Generate a real identity so LoadIdentity succeeds
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatal(err)
	}

	mgr := &mockServiceManager{installed: true}

	var buf bytes.Buffer
	err := RunUninstall(paths, store, mgr, false, "", strings.NewReader("y\n"), &buf)
	if err != nil {
		t.Fatalf("RunUninstall: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Agent process stopped.") {
		t.Errorf("expected agent stop message, got: %s", output)
	}
	if !strings.Contains(output, "Agent service uninstalled.") {
		t.Errorf("expected service uninstall message, got: %s", output)
	}
	if !strings.Contains(output, "Config directory removed") {
		t.Errorf("expected config removal message, got: %s", output)
	}
	if !strings.Contains(output, "PocketMux uninstalled successfully.") {
		t.Errorf("expected success message, got: %s", output)
	}

	// Config dir should be gone
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("config directory should have been removed")
	}

	// Private key should be deleted from store
	_, err = store.Get(auth.SecretKeyEd25519Private)
	if err == nil {
		t.Error("private key should have been deleted from secret store")
	}
}

func TestRunUninstall_KeepConfig(t *testing.T) {
	dir := t.TempDir()
	paths := testUninstallPaths(dir)

	if err := os.MkdirAll(paths.KeysDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.ConfigFile, []byte("name = \"test\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	store := auth.NewMemorySecretStore()
	_ = store.Set(auth.SecretKeyEd25519Private, []byte("fake-key-data"))

	mgr := &mockServiceManager{installed: true}

	var buf bytes.Buffer
	err := RunUninstall(paths, store, mgr, true, "", strings.NewReader("y\n"), &buf)
	if err != nil {
		t.Fatalf("RunUninstall: %v", err)
	}

	output := buf.String()

	if !strings.Contains(output, "Config and keys preserved (--keep-config).") {
		t.Errorf("expected keep-config message, got: %s", output)
	}

	// Config dir should still exist
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("config directory should have been preserved")
	}

	// Private key should NOT have been deleted
	_, err = store.Get(auth.SecretKeyEd25519Private)
	if err != nil {
		t.Error("private key should have been preserved in secret store")
	}
}

func TestRunUninstall_NoIdentity(t *testing.T) {
	dir := t.TempDir()
	paths := testUninstallPaths(dir)

	// No keys dir or identity — should skip server call gracefully
	store := auth.NewMemorySecretStore()
	mgr := &mockServiceManager{}

	var buf bytes.Buffer
	err := RunUninstall(paths, store, mgr, false, "", strings.NewReader("y\n"), &buf)
	if err != nil {
		t.Fatalf("RunUninstall: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No identity found, skipping server un-registration.") {
		t.Errorf("expected no-identity message, got: %s", output)
	}
	if !strings.Contains(output, "PocketMux uninstalled successfully.") {
		t.Errorf("expected success message, got: %s", output)
	}
}
