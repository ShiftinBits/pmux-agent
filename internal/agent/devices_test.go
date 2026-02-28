package agent

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

func TestRunDevices_NoPairedDevices(t *testing.T) {
	// Create temp dir with no paired devices file
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	var buf bytes.Buffer
	if err := RunDevices(path, store, &buf); err != nil {
		t.Fatalf("RunDevices: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No paired devices.") {
		t.Errorf("expected 'No paired devices.' in output, got: %s", output)
	}
}

func TestRunDevices_WithDevices(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	// Use time.Local for LastSeen so the formatted date matches regardless of
	// the system timezone (time.Unix uses local time for formatting).
	lastSeenTime := time.Date(2025, 6, 20, 14, 30, 0, 0, time.Local)

	// Write test devices using SavePairedDevices (metadata only)
	// and store shared secrets separately
	devices := []auth.PairedDevice{
		{
			DeviceID: "abc123def456abc123def456abc123de",
			Name:     "My Phone",
			PairedAt: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			LastSeen: lastSeenTime.Unix(),
		},
		{
			DeviceID: "xyz789012345xyz789012345xyz78901",
			Name:     "",
			PairedAt: time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC),
			LastSeen: 0,
		},
	}
	if err := auth.SavePairedDevices(path, devices); err != nil {
		t.Fatalf("SavePairedDevices: %v", err)
	}

	var buf bytes.Buffer
	if err := RunDevices(path, store, &buf); err != nil {
		t.Fatalf("RunDevices: %v", err)
	}

	output := buf.String()

	// Check header
	if !strings.Contains(output, "DEVICE ID") {
		t.Error("expected header with DEVICE ID")
	}
	if !strings.Contains(output, "NAME") {
		t.Error("expected header with NAME")
	}

	// Check device ID is truncated
	if !strings.Contains(output, "abc123def456...") {
		t.Errorf("expected truncated device ID 'abc123def456...', got: %s", output)
	}

	// Check named device
	if !strings.Contains(output, "My Phone") {
		t.Error("expected device name 'My Phone'")
	}

	// Check unnamed device shows (unnamed)
	if !strings.Contains(output, "(unnamed)") {
		t.Error("expected '(unnamed)' for device without name")
	}

	// Check last seen formatting (uses local time, matching time.Unix behavior)
	expectedLastSeen := lastSeenTime.Format("2006-01-02 15:04")
	if !strings.Contains(output, expectedLastSeen) {
		t.Errorf("expected last seen %q in output: %s", expectedLastSeen, output)
	}

	// Check "never" for device with no last seen
	if !strings.Contains(output, "never") {
		t.Error("expected 'never' for device with no last seen")
	}

	// Check paired date formatting
	if !strings.Contains(output, "2025-06-15") {
		t.Error("expected paired date '2025-06-15'")
	}
}

func TestRunDevices_DeviceIDTruncation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	devices := []auth.PairedDevice{
		{
			DeviceID: "short",
			PairedAt: time.Now(),
		},
	}
	if err := auth.SavePairedDevices(path, devices); err != nil {
		t.Fatalf("SavePairedDevices: %v", err)
	}

	var buf bytes.Buffer
	if err := RunDevices(path, store, &buf); err != nil {
		t.Fatalf("RunDevices: %v", err)
	}

	output := buf.String()
	// Short ID should NOT be truncated
	if !strings.Contains(output, "short") {
		t.Error("expected short device ID without truncation")
	}
	if strings.Contains(output, "short...") {
		t.Error("short device ID should NOT have '...' suffix")
	}
}
