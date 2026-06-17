package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunAgentDetail_NotRunning_NoPIDFile(t *testing.T) {
	paths := testPaths(t)

	var buf bytes.Buffer
	err := RunAgentDetail("1.2.3", paths, &buf)
	if !errors.Is(err, ErrAgentNotRunning) {
		t.Fatalf("expected ErrAgentNotRunning, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "pmux 1.2.3") {
		t.Errorf("expected version line, got: %s", output)
	}
	if !strings.Contains(output, "Agent is not running") {
		t.Errorf("expected 'Agent is not running', got: %s", output)
	}
}

func TestRunAgentDetail_StalePID(t *testing.T) {
	paths := testPaths(t)

	// Write a PID file with a bogus PID that won't be running
	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte("999999999"), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	var buf bytes.Buffer
	err := RunAgentDetail("1.2.3", paths, &buf)
	if !errors.Is(err, ErrAgentNotRunning) {
		t.Fatalf("expected ErrAgentNotRunning, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "pmux 1.2.3") {
		t.Errorf("expected version line, got: %s", output)
	}
	if !strings.Contains(output, "Agent is not running (stale PID file)") {
		t.Errorf("expected stale PID message, got: %s", output)
	}

	// PID file should be cleaned up
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Error("expected stale PID file to be removed")
	}
}

func TestRunAgentDetail_Running(t *testing.T) {
	paths := testPaths(t)

	// Use our own PID as a known-running process
	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	var buf bytes.Buffer
	err := RunAgentDetail("2.0.0", paths, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "pmux 2.0.0") {
		t.Errorf("expected version line, got: %s", output)
	}
	if !strings.Contains(output, fmt.Sprintf("Agent is running (PID %d)", os.Getpid())) {
		t.Errorf("expected running PID line, got: %s", output)
	}
}

func TestRunAgentDetail_Running_WithLogFile(t *testing.T) {
	paths := testPaths(t)

	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	// Write a log file with some lines
	logPath := filepath.Join(paths.ConfigDir, "agent.log")
	logContent := "line1\nline2\nline3\nline4\nline5\nline6\nline7\n"
	if err := os.WriteFile(logPath, []byte(logContent), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	var buf bytes.Buffer
	err := RunAgentDetail("2.0.0", paths, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Recent log:") {
		t.Errorf("expected 'Recent log:' section, got: %s", output)
	}
	// Should show last 5 lines (line3-line7)
	if !strings.Contains(output, "  line3") {
		t.Errorf("expected line3 in log tail, got: %s", output)
	}
	if !strings.Contains(output, "  line7") {
		t.Errorf("expected line7 in log tail, got: %s", output)
	}
	// line1 should have been trimmed off (only last 5)
	if strings.Contains(output, "  line1") {
		t.Errorf("expected line1 to be trimmed from log tail, got: %s", output)
	}
}

func TestRunAgentDetail_Running_NoLogFile(t *testing.T) {
	paths := testPaths(t)

	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	// No log file written — should not error or show "Recent log:"
	var buf bytes.Buffer
	err := RunAgentDetail("2.0.0", paths, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "Recent log:") {
		t.Errorf("expected no 'Recent log:' when log file missing, got: %s", output)
	}
}

func TestRunAgentDetail_Running_EmptyLogFile(t *testing.T) {
	paths := testPaths(t)

	pidPath := filepath.Join(paths.ConfigDir, pidFileName)
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		t.Fatalf("write PID file: %v", err)
	}

	// Write an empty log file
	logPath := filepath.Join(paths.ConfigDir, "agent.log")
	if err := os.WriteFile(logPath, []byte(""), 0600); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	var buf bytes.Buffer
	err := RunAgentDetail("2.0.0", paths, &buf)
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "Recent log:") {
		t.Errorf("expected no 'Recent log:' for empty log file, got: %s", output)
	}
}

// --- tailFile unit tests ---

func TestTailFile_ExactLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	if err := os.WriteFile(path, []byte("a\nb\nc\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	lines, err := tailFile(path, 3)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "a" || lines[1] != "b" || lines[2] != "c" {
		t.Errorf("unexpected lines: %v", lines)
	}
}

func TestTailFile_MoreLinesThanN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	if err := os.WriteFile(path, []byte("1\n2\n3\n4\n5\n6\n7\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	lines, err := tailFile(path, 3)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}
	if lines[0] != "5" || lines[1] != "6" || lines[2] != "7" {
		t.Errorf("expected last 3 lines [5,6,7], got: %v", lines)
	}
}

func TestTailFile_FewerLinesThanN(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	if err := os.WriteFile(path, []byte("only\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	lines, err := tailFile(path, 5)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if lines[0] != "only" {
		t.Errorf("expected 'only', got: %s", lines[0])
	}
}

func TestTailFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")
	if err := os.WriteFile(path, []byte(""), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	lines, err := tailFile(path, 5)
	if err != nil {
		t.Fatalf("tailFile: %v", err)
	}
	if len(lines) != 0 {
		t.Errorf("expected 0 lines for empty file, got %d", len(lines))
	}
}

func TestTailFile_FileNotFound(t *testing.T) {
	_, err := tailFile("/nonexistent/path/file.log", 5)
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}
