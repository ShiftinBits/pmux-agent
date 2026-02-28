package agent

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

func writePairedDevices(t *testing.T, path string, store auth.SecretStore) {
	t.Helper()
	devices := []auth.PairedDevice{
		{
			DeviceID: "abc123def456abc123def456abc123de",
			Name:     "My Phone",
			PairedAt: time.Now(),
		},
		{
			DeviceID: "abc999888777abc999888777abc99988",
			Name:     "Tablet",
			PairedAt: time.Now(),
		},
		{
			DeviceID: "xyz789012345xyz789012345xyz78901",
			Name:     "",
			PairedAt: time.Now(),
		},
	}
	// SavePairedDevices writes metadata to disk (SharedSecret excluded via json:"-")
	if err := auth.SavePairedDevices(path, devices); err != nil {
		t.Fatalf("SavePairedDevices: %v", err)
	}
}

func TestRunUnpair_NoArgs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	var out bytes.Buffer
	in := strings.NewReader("")

	if err := RunUnpair(nil, path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "Usage: pmux unpair") {
		t.Errorf("expected usage message, got: %s", out.String())
	}
}

func TestRunUnpair_UnknownDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()
	writePairedDevices(t, path, store)

	var out bytes.Buffer
	in := strings.NewReader("")

	if err := RunUnpair([]string{"zzz"}, path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "No device found matching") {
		t.Errorf("expected no-match message, got: %s", out.String())
	}
}

func TestRunUnpair_AmbiguousPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()
	writePairedDevices(t, path, store)

	var out bytes.Buffer
	in := strings.NewReader("")

	// "abc" matches both abc123... and abc999...
	if err := RunUnpair([]string{"abc"}, path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Ambiguous prefix") {
		t.Errorf("expected ambiguous message, got: %s", output)
	}
	if !strings.Contains(output, "My Phone") {
		t.Error("expected 'My Phone' in ambiguous list")
	}
	if !strings.Contains(output, "Tablet") {
		t.Error("expected 'Tablet' in ambiguous list")
	}
}

func TestRunUnpair_ConfirmedRemoval(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()
	writePairedDevices(t, path, store)

	var out bytes.Buffer
	in := strings.NewReader("y\n")

	// "xyz" uniquely matches the third device
	if err := RunUnpair([]string{"xyz"}, path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "scan a new QR code") {
		t.Errorf("expected QR code warning in prompt, got: %s", output)
	}
	if !strings.Contains(output, "unpaired successfully") {
		t.Errorf("expected success message, got: %s", output)
	}

	// Verify device was actually removed from disk
	devices, err := auth.LoadPairedDevices(path, store)
	if err != nil {
		t.Fatalf("LoadPairedDevices: %v", err)
	}
	for _, d := range devices {
		if strings.HasPrefix(d.DeviceID, "xyz") {
			t.Error("device should have been removed")
		}
	}
	if len(devices) != 2 {
		t.Errorf("expected 2 remaining devices, got %d", len(devices))
	}
}

func TestRunUnpair_EmptyPrefix(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	var out bytes.Buffer
	in := strings.NewReader("")

	if err := RunUnpair([]string{""}, path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	if !strings.Contains(out.String(), "Usage: pmux unpair") {
		t.Errorf("expected usage message for empty prefix, got: %s", out.String())
	}
}

func TestRunUnpair_EOFCancels(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()
	writePairedDevices(t, path, store)

	var out bytes.Buffer
	in := strings.NewReader("") // EOF — no input

	if err := RunUnpair([]string{"xyz"}, path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Cancelled") {
		t.Errorf("expected cancelled on EOF, got: %s", output)
	}

	// Verify device was NOT removed
	devices, err := auth.LoadPairedDevices(path, store)
	if err != nil {
		t.Fatalf("LoadPairedDevices: %v", err)
	}
	if len(devices) != 3 {
		t.Errorf("expected 3 devices (unchanged), got %d", len(devices))
	}
}

func TestRunUnpair_Cancelled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()
	writePairedDevices(t, path, store)

	var out bytes.Buffer
	in := strings.NewReader("n\n")

	if err := RunUnpair([]string{"xyz"}, path, store, in, &out); err != nil {
		t.Fatalf("RunUnpair: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Cancelled") {
		t.Errorf("expected cancelled message, got: %s", output)
	}

	// Verify device was NOT removed
	devices, err := auth.LoadPairedDevices(path, store)
	if err != nil {
		t.Fatalf("LoadPairedDevices: %v", err)
	}
	if len(devices) != 3 {
		t.Errorf("expected 3 devices (unchanged), got %d", len(devices))
	}
}
