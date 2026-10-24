package agent

import (
	"bytes"
	"errors"
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

func TestRunAgentStart_NoIdentity(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	var buf bytes.Buffer
	err := RunAgentStart(paths, store, &buf)
	if !errors.Is(err, errNoIdentity) {
		t.Fatalf("expected errNoIdentity, got: %v", err)
	}
	if strings.Contains(buf.String(), "Agent started") {
		t.Errorf("must not report 'Agent started', got: %q", buf.String())
	}
}

func TestRunAgentStart_StoreError(t *testing.T) {
	paths := testPaths(t)
	if _, err := auth.GenerateIdentity(paths.KeysDir, auth.NewMemorySecretStore()); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	storeErr := errors.New("keychain locked")

	err := RunAgentStart(paths, failingStore{err: storeErr}, &bytes.Buffer{})
	if !errors.Is(err, storeErr) || errors.Is(err, errNoIdentity) {
		t.Fatalf("expected the store error, got: %v", err)
	}
}
