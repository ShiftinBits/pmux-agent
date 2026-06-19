package agent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

// Restart when nothing is running must NOT error (unlike a bare stop) — it just
// starts the agent.
func TestRunAgentRestart_NotRunning_StartsAnyway(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore() // no identity → EnsureRunning is a no-op

	var buf bytes.Buffer
	if err := RunAgentRestart(paths, store, &buf); err != nil {
		t.Fatalf("expected nil error when agent not running, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Agent is not running") {
		t.Errorf("expected 'not running' note, got: %q", output)
	}
	if !strings.Contains(output, "Agent started") {
		t.Errorf("expected 'Agent started', got: %q", output)
	}
}

// A stale PID file is cleaned up by the stop phase, then the agent starts.
func TestRunAgentRestart_StalePID_Restarts(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

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
	store := auth.NewMemorySecretStore()

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
