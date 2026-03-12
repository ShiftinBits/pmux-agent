package agent

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

// mockStartServiceManager provides configurable IsInstalled and Start behavior.
type mockStartServiceManager struct {
	mockServiceManager
	startErr error
}

func (m *mockStartServiceManager) Start() error { return m.startErr }

func TestRunAgentStart_AlreadyRunning(t *testing.T) {
	paths := testPaths(t)

	// Write a PID file with our own PID (guaranteed to be running)
	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	mgr := &mockStartServiceManager{
		mockServiceManager: mockServiceManager{installed: false},
	}

	var buf bytes.Buffer
	err := RunAgentStart(paths, nil, mgr, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent is already running") {
		t.Errorf("expected 'already running' message, got: %q", output)
	}
	if !strings.Contains(output, fmt.Sprintf("PID %d", os.Getpid())) {
		t.Errorf("expected PID in message, got: %q", output)
	}
}

func TestRunAgentStart_ServiceInstalled_StartSucceeds(t *testing.T) {
	paths := testPaths(t)

	mgr := &mockStartServiceManager{
		mockServiceManager: mockServiceManager{installed: true},
		startErr:           nil,
	}

	var buf bytes.Buffer
	err := RunAgentStart(paths, nil, mgr, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent started (via service manager)") {
		t.Errorf("expected service manager start message, got: %q", output)
	}
}

func TestRunAgentStart_ServiceStartFails_FallsThrough(t *testing.T) {
	paths := testPaths(t)

	mgr := &mockStartServiceManager{
		mockServiceManager: mockServiceManager{installed: true},
		startErr:           fmt.Errorf("launchctl failed"),
	}

	// No identity → EnsureRunning returns nil (nothing to start)
	store := auth.NewMemorySecretStore()

	var buf bytes.Buffer
	err := RunAgentStart(paths, store, mgr, &buf)
	if err != nil {
		t.Fatalf("expected nil error (EnsureRunning no-op without identity), got: %v", err)
	}

	output := buf.String()
	// Should NOT contain "via service manager" — that path failed
	if strings.Contains(output, "via service manager") {
		t.Errorf("should not report service manager success, got: %q", output)
	}
	// Should contain "Agent started" from the direct spawn path
	if !strings.Contains(output, "Agent started") {
		t.Errorf("expected 'Agent started' message, got: %q", output)
	}
}

func TestRunAgentStart_NoServiceInstalled_DirectSpawn(t *testing.T) {
	paths := testPaths(t)

	mgr := &mockStartServiceManager{
		mockServiceManager: mockServiceManager{installed: false},
	}

	// No identity → EnsureRunning returns nil (no-op)
	store := auth.NewMemorySecretStore()

	var buf bytes.Buffer
	err := RunAgentStart(paths, store, mgr, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent started") {
		t.Errorf("expected 'Agent started' message, got: %q", output)
	}
	if strings.Contains(output, "via service manager") {
		t.Errorf("should not mention service manager, got: %q", output)
	}
}
