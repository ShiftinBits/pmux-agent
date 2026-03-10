package agent

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		t.Fatalf("create keys dir: %v", err)
	}
	return config.Paths{
		ConfigDir:     dir,
		KeysDir:       keysDir,
		PairedDevices: filepath.Join(dir, "paired_devices.json"),
		ConfigFile:    filepath.Join(dir, "config.toml"),
	}
}

func writeSinglePairedDevice(t *testing.T, path string) {
	t.Helper()
	devices := []auth.PairedDevice{
		{
			DeviceID: "abc123def456abc123def456abc123de",
			Name:     "My Phone",
			PairedAt: time.Now(),
		},
	}
	if err := auth.SavePairedDevices(path, devices); err != nil {
		t.Fatalf("SavePairedDevices: %v", err)
	}
}

func TestRunUnpair_NoDevice(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	var out bytes.Buffer
	in := strings.NewReader("")

	if err := RunUnpair(paths, store, "", in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "No device paired.") {
		t.Errorf("expected 'No device paired.' message, got: %s", out.String())
	}
}

func TestRunUnpair_Confirmed(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	writeSinglePairedDevice(t, paths.PairedDevices)

	var out bytes.Buffer
	in := strings.NewReader("y\n")

	if err := RunUnpair(paths, store, "", in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "My Phone") {
		t.Errorf("expected device name in prompt, got: %s", output)
	}
	if !strings.Contains(output, "scan a new QR code") {
		t.Errorf("expected QR code warning, got: %s", output)
	}
	if !strings.Contains(output, "unpaired successfully") {
		t.Errorf("expected success message, got: %s", output)
	}

	// Verify device was removed
	device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device != nil {
		t.Error("device should have been removed")
	}
}

func TestRunUnpair_Cancelled(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	writeSinglePairedDevice(t, paths.PairedDevices)

	var out bytes.Buffer
	in := strings.NewReader("n\n")

	if err := RunUnpair(paths, store, "", in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "Cancelled") {
		t.Errorf("expected 'Cancelled', got: %s", out.String())
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

func TestRunUnpair_EOFCancels(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	writeSinglePairedDevice(t, paths.PairedDevices)

	var out bytes.Buffer
	in := strings.NewReader("") // EOF

	if err := RunUnpair(paths, store, "", in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "Cancelled") {
		t.Errorf("expected 'Cancelled' on EOF, got: %s", out.String())
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

func TestRunUnpair_NotifiesServer(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	// Generate identity so LoadIdentity succeeds
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	writeSinglePairedDevice(t, paths.PairedDevices)

	var deleteCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/token" && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt"}`))
		case r.URL.Path == "/auth/pairing" && r.Method == "DELETE":
			deleteCalled.Store(true)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Write config pointing to test server
	cfgContent := "[server]\nurl = " + `"` + server.URL + `"` + "\n"
	if err := writeFile(t, paths.ConfigFile, cfgContent); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out bytes.Buffer
	in := strings.NewReader("y\n")

	if err := RunUnpair(paths, store, "", in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !deleteCalled.Load() {
		t.Error("expected DELETE /auth/pairing to be called")
	}

	if !strings.Contains(out.String(), "unpaired successfully") {
		t.Errorf("expected success message, got: %s", out.String())
	}

	// Verify device was removed
	device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device != nil {
		t.Error("device should have been removed")
	}
}

func TestRunUnpair_ServerFailureContinues(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	// Generate identity so LoadIdentity succeeds
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	writeSinglePairedDevice(t, paths.PairedDevices)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/token" && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt"}`))
		case r.URL.Path == "/auth/pairing" && r.Method == "DELETE":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal error"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Write config pointing to test server
	cfgContent := "[server]\nurl = " + `"` + server.URL + `"` + "\n"
	if err := writeFile(t, paths.ConfigFile, cfgContent); err != nil {
		t.Fatalf("write config: %v", err)
	}

	var out bytes.Buffer
	in := strings.NewReader("y\n")

	if err := RunUnpair(paths, store, "", in, &out); err != nil {
		t.Fatalf("RunUnpair should succeed even if server fails: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Warning: could not notify server") {
		t.Errorf("expected server warning, got: %s", output)
	}
	if !strings.Contains(output, "unpaired successfully") {
		t.Errorf("expected success message, got: %s", output)
	}

	// Verify device was still removed locally
	device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device != nil {
		t.Error("device should have been removed despite server failure")
	}
}

func writeFile(t *testing.T, path, content string) error {
	t.Helper()
	return os.WriteFile(path, []byte(content), 0600)
}
