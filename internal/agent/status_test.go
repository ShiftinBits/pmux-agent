package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/firewall"
	"github.com/shiftinbits/pmux-agent/internal/service"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

// --- Test mocks ---

type mockSessionLister struct {
	sessions []tmux.Session
	err      error
}

func (m *mockSessionLister) ListSessions() ([]tmux.Session, error) {
	return m.sessions, m.err
}

type mockServiceManager struct {
	installed bool
}

func (m *mockServiceManager) IsInstalled() bool { return m.installed }
func (m *mockServiceManager) Status() (service.Status, error) {
	return service.Status{Installed: m.installed}, nil
}
func (m *mockServiceManager) Install() error   { return nil }
func (m *mockServiceManager) Uninstall() error { return nil }
func (m *mockServiceManager) Start() error     { return nil }
func (m *mockServiceManager) Stop() error      { return nil }

// --- Helper ---

func testStatusParams(dir string, store auth.SecretStore) StatusParams {
	return StatusParams{
		Version:           "0.1.0-test",
		PairedDevicesPath: filepath.Join(dir, "paired_devices.json"),
		Store:             store,
		PIDFilePath:       filepath.Join(dir, "nonexistent.pid"),
		ServiceManager:    &mockServiceManager{installed: false},
		Sessions:          &mockSessionLister{},
	}
}

// --- Tests ---

func TestRunStatus_NoDevice(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewMemorySecretStore()
	params := testStatusParams(dir, store)

	var buf bytes.Buffer
	if err := RunStatus(params, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Version:  0.1.0-test") {
		t.Errorf("expected 'Version:  0.1.0-test', got: %s", output)
	}
	if !strings.Contains(output, "Agent:    not running") {
		t.Errorf("expected 'Agent:    not running', got: %s", output)
	}
	if !strings.Contains(output, "Service:  not installed") {
		t.Errorf("expected 'Service:  not installed', got: %s", output)
	}
	if !strings.Contains(output, "Sessions: 0") {
		t.Errorf("expected 'Sessions: 0', got: %s", output)
	}
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

	devices := []auth.PairedDevice{
		{
			DeviceID: "abc123def456abc123def456abc123de",
			Name:     "My Phone",
		},
	}
	if err := auth.SavePairedDevices(path, devices); err != nil {
		t.Fatalf("SavePairedDevices: %v", err)
	}

	params := testStatusParams(dir, store)
	params.PairedDevicesPath = path
	params.ServiceManager = &mockServiceManager{installed: true}
	params.Sessions = &mockSessionLister{
		sessions: []tmux.Session{
			{ID: "$0", Name: "main"},
			{ID: "$1", Name: "work"},
		},
	}

	// Write a PID file with the current process PID to simulate "running"
	pidPath := filepath.Join(dir, "agent.pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}
	params.PIDFilePath = pidPath

	var buf bytes.Buffer
	if err := RunStatus(params, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent:    running (PID") {
		t.Errorf("expected agent running line, got: %s", output)
	}
	if !strings.Contains(output, "Service:  installed") {
		t.Errorf("expected 'Service:  installed', got: %s", output)
	}
	if !strings.Contains(output, "Sessions: 2") {
		t.Errorf("expected 'Sessions: 2', got: %s", output)
	}
	// Named device: header shows name, Device ID line shows truncated ID
	if !strings.Contains(output, "Paired device: My Phone") {
		t.Errorf("expected 'Paired device: My Phone', got: %s", output)
	}
	if !strings.Contains(output, "Device ID:  abc123def456...") {
		t.Errorf("expected truncated device ID line, got: %s", output)
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
		},
	}
	if err := auth.SavePairedDevices(path, devices); err != nil {
		t.Fatalf("SavePairedDevices: %v", err)
	}

	params := testStatusParams(dir, store)
	params.PairedDevicesPath = path

	var buf bytes.Buffer
	if err := RunStatus(params, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	output := buf.String()
	// Unnamed device: header shows truncated ID, no separate Device ID line
	if !strings.Contains(output, "Paired device: abc123def456...") {
		t.Errorf("expected device ID as header for unnamed device, got: %s", output)
	}
	// Should NOT have a redundant Device ID line
	if strings.Contains(output, "Device ID:") {
		t.Errorf("expected no Device ID line for unnamed device, got: %s", output)
	}
}

func TestRunStatus_SessionListError(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewMemorySecretStore()
	params := testStatusParams(dir, store)
	params.Sessions = &mockSessionLister{err: fmt.Errorf("tmux not found")}

	var buf bytes.Buffer
	if err := RunStatus(params, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Sessions: unknown") {
		t.Errorf("expected 'Sessions: unknown' on error, got: %s", output)
	}
}

func TestRunStatus_StalePID(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewMemorySecretStore()
	params := testStatusParams(dir, store)

	// Write a PID file with a bogus PID that won't be running
	pidPath := filepath.Join(dir, "agent.pid")
	if err := os.WriteFile(pidPath, []byte("999999999"), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}
	params.PIDFilePath = pidPath

	var buf bytes.Buffer
	if err := RunStatus(params, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent:    not running") {
		t.Errorf("expected 'Agent:    not running' for stale PID, got: %s", output)
	}
}

func TestRunStatusFirewallLine(t *testing.T) {
	dir := t.TempDir()
	store := auth.NewMemorySecretStore()
	params := testStatusParams(dir, store)
	params.FirewallStatus = &firewall.Status{
		Supported:       true,
		FirewallEnabled: true,
		Authorized:      false,
		Confidence:      firewall.ConfidenceHigh,
		Path:            "/x/pmux",
		Detail:          "not in allow-list",
	}

	var buf bytes.Buffer
	if err := RunStatus(params, &buf); err != nil {
		t.Fatalf("RunStatus: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Firewall:") || !strings.Contains(out, "NOT authorized") || !strings.Contains(out, "firewall-allow") {
		t.Errorf("expected firewall NOT-authorized line, got:\n%s", out)
	}
}
