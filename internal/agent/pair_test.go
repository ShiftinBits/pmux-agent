package agent

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

func TestRunPair_NoIdentity(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()
	mgr := &mockServiceManager{}

	var out bytes.Buffer
	in := strings.NewReader("")

	err := RunPair(paths, cfg, store, mgr, "", in, &out)
	if err == nil {
		t.Fatal("expected error when no identity exists")
	}
	if !strings.Contains(err.Error(), "no identity found") {
		t.Errorf("expected 'no identity found' error, got: %v", err)
	}
}

func TestRunPair_ExistingPairing_UserDeclines(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()
	mgr := &mockServiceManager{}

	// Generate identity so HasIdentity passes
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// Write an existing paired device
	err := auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID: "abc123def456abc123def456abc123de",
		Name:     "Test Phone",
		PairedAt: time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}

	var out bytes.Buffer
	in := strings.NewReader("n\n")

	if err := RunPair(paths, cfg, store, mgr, "", in, &out); err != nil {
		t.Fatalf("RunPair should return nil on decline, got: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Test Phone") {
		t.Errorf("expected device name in prompt, got: %s", output)
	}
	if !strings.Contains(output, "Replace it?") {
		t.Errorf("expected 'Replace it?' prompt, got: %s", output)
	}
	if !strings.Contains(output, "Pairing cancelled.") {
		t.Errorf("expected 'Pairing cancelled.' message, got: %s", output)
	}

	// Verify device was NOT removed
	device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device == nil {
		t.Error("device should NOT have been removed")
	}
}

func TestRunPair_ExistingPairing_EOFDeclines(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()
	mgr := &mockServiceManager{}

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	err := auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID: "abc123def456abc123def456abc123de",
		Name:     "Test Phone",
		PairedAt: time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}

	var out bytes.Buffer
	in := strings.NewReader("") // EOF

	if err := RunPair(paths, cfg, store, mgr, "", in, &out); err != nil {
		t.Fatalf("RunPair should return nil on EOF, got: %v", err)
	}

	if !strings.Contains(out.String(), "Pairing cancelled.") {
		t.Errorf("expected 'Pairing cancelled.' on EOF, got: %s", out.String())
	}
}

func TestRunPair_HTTPWarning_NonLocalServer(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	mgr := &mockServiceManager{}

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// Config with HTTP non-local server URL
	cfg := config.Defaults()
	cfg.Server.URL = "http://example.com"

	var out bytes.Buffer
	in := strings.NewReader("")

	// This will error at InitiatePairing (connection refused), but the
	// HTTP warning should appear in output before that.
	_ = RunPair(paths, cfg, store, mgr, "", in, &out)

	output := out.String()
	if !strings.Contains(output, "WARNING: Server URL") {
		t.Errorf("expected HTTP warning for non-local server, got: %s", output)
	}
	if !strings.Contains(output, "unencrypted HTTP") {
		t.Errorf("expected 'unencrypted HTTP' in warning, got: %s", output)
	}
}

func TestRunPair_NoHTTPWarning_Localhost(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	mgr := &mockServiceManager{}

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	cfg := config.Defaults()
	cfg.Server.URL = "http://localhost:8787"

	var out bytes.Buffer
	in := strings.NewReader("")

	// Will error at InitiatePairing, but no warning should appear
	_ = RunPair(paths, cfg, store, mgr, "", in, &out)

	output := out.String()
	if strings.Contains(output, "WARNING") {
		t.Errorf("expected no HTTP warning for localhost, got: %s", output)
	}
}

func TestRunPair_NoHTTPWarning_HTTPS(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	mgr := &mockServiceManager{}

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	cfg := config.Defaults()
	cfg.Server.URL = "https://signal.pmux.io"

	var out bytes.Buffer
	in := strings.NewReader("")

	// Will error at InitiatePairing, but no warning should appear
	_ = RunPair(paths, cfg, store, mgr, "", in, &out)

	output := out.String()
	if strings.Contains(output, "WARNING") {
		t.Errorf("expected no HTTP warning for HTTPS URL, got: %s", output)
	}
}

func TestRunPair_ExistingPairing_AcceptButServerDown(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	mgr := &mockServiceManager{}

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	err := auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID: "abc123def456abc123def456abc123de",
		Name:     "Old Phone",
		PairedAt: time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}

	// Point to a server that will refuse connections
	cfg := config.Defaults()
	cfg.Server.URL = "http://127.0.0.1:1"

	var out bytes.Buffer
	in := strings.NewReader("y\n")

	err = RunPair(paths, cfg, store, mgr, "", in, &out)
	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
	if !strings.Contains(err.Error(), "failed to initiate pairing") {
		t.Errorf("expected 'failed to initiate pairing' error, got: %v", err)
	}

	// Verify old device was removed (user accepted replacement)
	device, loadErr := auth.LoadPairedDevice(paths.PairedDevices, store)
	if loadErr != nil {
		t.Fatalf("LoadPairedDevice: %v", loadErr)
	}
	if device != nil {
		t.Error("old device should have been removed after user accepted replacement")
	}
}
