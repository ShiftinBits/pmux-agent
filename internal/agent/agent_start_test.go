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

func TestRunAgentStart_AlreadyRunning(t *testing.T) {
	paths := testPaths(t)

	// Write a PID file with our own PID (guaranteed to be running)
	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	var buf bytes.Buffer
	err := RunAgentStart(paths, nil, &buf)
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

func TestRunAgentStart_DirectSpawn(t *testing.T) {
	paths := testPaths(t)

	// No identity → EnsureRunning returns nil (no-op)
	store := auth.NewMemorySecretStore()

	var buf bytes.Buffer
	err := RunAgentStart(paths, store, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent started") {
		t.Errorf("expected 'Agent started' message, got: %q", output)
	}
}
