package agent

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

func TestRunStatus_NoDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	var buf bytes.Buffer
	if err := RunStatus(path, store, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No device paired.") {
		t.Errorf("expected 'No device paired.' message, got: %s", output)
	}
	if !strings.Contains(output, "pmux pair") {
		t.Errorf("expected 'pmux pair' hint, got: %s", output)
	}
}

func TestRunStatus_WithDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	lastSeenTime := time.Date(2025, 6, 20, 14, 30, 0, 0, time.Local)

	devices := []auth.PairedDevice{
		{
			DeviceID: "abc123def456abc123def456abc123de",
			Name:     "My Phone",
			PairedAt: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			LastSeen: lastSeenTime.Unix(),
		},
	}
	if err := auth.SavePairedDevices(path, devices); err != nil {
		t.Fatalf("SavePairedDevices: %v", err)
	}

	var buf bytes.Buffer
	if err := RunStatus(path, store, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Paired device: My Phone") {
		t.Errorf("expected 'Paired device: My Phone', got: %s", output)
	}
	if !strings.Contains(output, "abc123def456...") {
		t.Errorf("expected truncated device ID, got: %s", output)
	}
	if !strings.Contains(output, "2025-06-15") {
		t.Errorf("expected paired date, got: %s", output)
	}
	expectedLastSeen := lastSeenTime.Format("2006-01-02 15:04")
	if !strings.Contains(output, expectedLastSeen) {
		t.Errorf("expected last seen %q, got: %s", expectedLastSeen, output)
	}
}

func TestRunStatus_UnnamedDevice(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "paired_devices.json")
	store := auth.NewMemorySecretStore()

	devices := []auth.PairedDevice{
		{
			DeviceID: "abc123def456abc123def456abc123de",
			Name:     "",
			PairedAt: time.Date(2025, 6, 15, 0, 0, 0, 0, time.UTC),
			LastSeen: 0,
		},
	}
	if err := auth.SavePairedDevices(path, devices); err != nil {
		t.Fatalf("SavePairedDevices: %v", err)
	}

	var buf bytes.Buffer
	if err := RunStatus(path, store, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "abc123def456...") {
		t.Errorf("expected device ID as header for unnamed device, got: %s", output)
	}
	if !strings.Contains(output, "never") {
		t.Errorf("expected 'never' for last seen, got: %s", output)
	}
}
