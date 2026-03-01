package agent

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

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
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	var out bytes.Buffer
	in := strings.NewReader("")

	if err := RunUnpair(path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "No device paired.") {
		t.Errorf("expected 'No device paired.' message, got: %s", out.String())
	}
}

func TestRunUnpair_Confirmed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()
	writeSinglePairedDevice(t, path)

	var out bytes.Buffer
	in := strings.NewReader("y\n")

	if err := RunUnpair(path, store, in, &out); err != nil {
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
	device, err := auth.LoadPairedDevice(path, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device != nil {
		t.Error("device should have been removed")
	}
}

func TestRunUnpair_Cancelled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()
	writeSinglePairedDevice(t, path)

	var out bytes.Buffer
	in := strings.NewReader("n\n")

	if err := RunUnpair(path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "Cancelled") {
		t.Errorf("expected 'Cancelled', got: %s", out.String())
	}

	// Verify device was NOT removed
	device, err := auth.LoadPairedDevice(path, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device == nil {
		t.Error("device should NOT have been removed")
	}
}

func TestRunUnpair_EOFCancels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()
	writeSinglePairedDevice(t, path)

	var out bytes.Buffer
	in := strings.NewReader("") // EOF

	if err := RunUnpair(path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "Cancelled") {
		t.Errorf("expected 'Cancelled' on EOF, got: %s", out.String())
	}

	// Verify device was NOT removed
	device, err := auth.LoadPairedDevice(path, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device == nil {
		t.Error("device should NOT have been removed")
	}
}
