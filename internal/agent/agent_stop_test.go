package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAgentStop_NoPIDFile_ReturnsErrAgentNotRunning(t *testing.T) {
	paths := testPaths(t)

	var buf bytes.Buffer
	err := RunAgentStop(paths, &buf)
	if !errors.Is(err, ErrAgentNotRunning) {
		t.Fatalf("expected ErrAgentNotRunning, got: %v", err)
	}
}

func TestRunAgentStop_StalePID_CleansUpReturnsNil(t *testing.T) {
	paths := testPaths(t)

	// Write a PID file with a bogus PID that won't be running
	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte("999999999"), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	var buf bytes.Buffer
	err := RunAgentStop(paths, &buf)
	if err != nil {
		t.Fatalf("expected nil error for stale PID, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "stale PID file cleaned up") {
		t.Errorf("expected stale PID cleanup message, got: %q", output)
	}

	// PID file should be removed
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("expected PID file to be removed after stale cleanup")
	}
}

func TestRunAgentStop_ProcessRunning_SIGTERMSent(t *testing.T) {
	paths := testPaths(t)

	// Start a real subprocess that we can signal
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start subprocess: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pid := cmd.Process.Pid

	// Write a PID file pointing to our subprocess
	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", pid)), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	var buf bytes.Buffer
	err := RunAgentStop(paths, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	// Should report either "Agent stopped" or "Agent forcefully killed"
	if !strings.Contains(output, "Agent stopped") && !strings.Contains(output, "Agent forcefully killed") {
		t.Errorf("expected stop confirmation message, got: %q", output)
	}

	// PID file should be removed
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("expected PID file to be removed after stop")
	}
}
