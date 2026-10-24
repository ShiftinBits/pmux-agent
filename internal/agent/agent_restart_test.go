package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

// With no identity restart fails up front, before the stop phase runs.
func TestRunAgentRestart_NotRunning_NoIdentity(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	var buf bytes.Buffer
	err := RunAgentRestart(paths, store, &buf)
	if !errors.Is(err, errNoIdentity) {
		t.Fatalf("expected errNoIdentity, got: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "Agent was not running") || strings.Contains(output, "Agent started") {
		t.Errorf("must not stop or start anything, got: %q", output)
	}
}

// A running agent must not be stopped when the identity pre-check fails.
func TestRunAgentRestart_NoIdentity_DoesNotStop(t *testing.T) {
	paths := testPaths(t)
	origStop := runAgentStop
	t.Cleanup(func() { runAgentStop = origStop })
	stopCalled := false
	runAgentStop = func(config.Paths, io.Writer) error {
		stopCalled = true
		return nil
	}

	err := RunAgentRestart(paths, auth.NewMemorySecretStore(), &bytes.Buffer{})
	if !errors.Is(err, errNoIdentity) {
		t.Fatalf("expected errNoIdentity, got: %v", err)
	}
	if stopCalled {
		t.Error("RunAgentStop must not be called when there is no identity")
	}
}

// A secret store failure is surfaced, not reported as a missing identity.
func TestRunAgentRestart_StoreError_DoesNotStop(t *testing.T) {
	paths := testPaths(t)
	if _, err := auth.GenerateIdentity(paths.KeysDir, auth.NewMemorySecretStore()); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	storeErr := errors.New("keychain locked")
	origStop := runAgentStop
	t.Cleanup(func() { runAgentStop = origStop })
	stopCalled := false
	runAgentStop = func(config.Paths, io.Writer) error {
		stopCalled = true
		return nil
	}

	err := RunAgentRestart(paths, failingStore{err: storeErr}, &bytes.Buffer{})
	if !errors.Is(err, storeErr) || errors.Is(err, errNoIdentity) {
		t.Fatalf("expected the store error, got: %v", err)
	}
	if stopCalled {
		t.Error("RunAgentStop must not be called when the secret store fails")
	}
}

// failingStore is a SecretStore whose Get always fails with err.
type failingStore struct {
	auth.SecretStore
	err error
}

func (s failingStore) Get(string) ([]byte, error) { return nil, s.err }

func newIdentityStore(t *testing.T, paths config.Paths) auth.SecretStore {
	t.Helper()
	store := auth.NewMemorySecretStore()
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return store
}

// A hard (non-sentinel) stop failure must short-circuit: start is not attempted,
// and the error propagates — otherwise a failed stop could leave two agents.
func TestRunAgentRestart_StopHardError_DoesNotStart(t *testing.T) {
	paths := testPaths(t)

	stopErr := errors.New("stop failed hard")
	origStop, origStart := runAgentStop, runAgentStart
	t.Cleanup(func() { runAgentStop, runAgentStart = origStop, origStart })

	startCalled := false
	runAgentStop = func(config.Paths, io.Writer) error { return stopErr }
	runAgentStart = func(config.Paths, auth.SecretStore, io.Writer) error {
		startCalled = true
		return nil
	}

	var buf bytes.Buffer
	err := RunAgentRestart(paths, newIdentityStore(t, paths), &buf)
	if !errors.Is(err, stopErr) {
		t.Fatalf("expected the stop error to propagate, got: %v", err)
	}
	if startCalled {
		t.Error("RunAgentStart must not be called when stop fails")
	}
}

// A stale PID file is cleaned up by the stop phase, then the agent starts.
func TestRunAgentRestart_StalePID_Restarts(t *testing.T) {
	paths := testPaths(t)
	store := newIdentityStore(t, paths)
	origStart := runAgentStart
	t.Cleanup(func() { runAgentStart = origStart })
	runAgentStart = func(_ config.Paths, _ auth.SecretStore, w io.Writer) error {
		fmt.Fprint(w, "Agent started\n")
		return nil
	}

	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte("999999999"), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	var buf bytes.Buffer
	if err := RunAgentRestart(paths, store, &buf); err != nil {
		t.Fatalf("expected nil error for stale PID restart, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent started") {
		t.Errorf("expected 'Agent started', got: %q", output)
	}
}

// A live agent is stopped (SIGTERM, PID file removed) then started again.
func TestRunAgentRestart_Running_StopsThenStarts(t *testing.T) {
	paths := testPaths(t)
	store := newIdentityStore(t, paths)
	origStart := runAgentStart
	t.Cleanup(func() { runAgentStart = origStart })
	runAgentStart = func(_ config.Paths, _ auth.SecretStore, w io.Writer) error {
		fmt.Fprint(w, "Agent started\n")
		return nil
	}

	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start subprocess: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", cmd.Process.Pid)), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	var buf bytes.Buffer
	if err := RunAgentRestart(paths, store, &buf); err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent stopped") && !strings.Contains(output, "Agent forcefully killed") {
		t.Errorf("expected stop confirmation, got: %q", output)
	}
	if !strings.Contains(output, "Agent started") {
		t.Errorf("expected 'Agent started', got: %q", output)
	}
}
