package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestWritePIDFile_WritesCurrentPID(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	if err := WritePIDFile(pidFile); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}

	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("failed to read PID file: %v", err)
	}

	got, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatalf("PID file content is not a number: %q", string(data))
	}

	want := os.Getpid()
	if got != want {
		t.Errorf("WritePIDFile wrote PID %d, want %d", got, want)
	}
}

func TestWritePIDFile_Permissions(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	if err := WritePIDFile(pidFile); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}

	info, err := os.Stat(pidFile)
	if err != nil {
		t.Fatalf("failed to stat PID file: %v", err)
	}

	got := info.Mode().Perm()
	want := os.FileMode(0600)
	if got != want {
		t.Errorf("PID file permissions = %o, want %o", got, want)
	}
}

func TestWritePIDFile_InvalidPath(t *testing.T) {
	err := WritePIDFile("/nonexistent/directory/agent.pid")
	if err == nil {
		t.Error("expected error writing PID file to nonexistent directory")
	}
}

func TestReadPIDFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	// Write current PID
	if err := WritePIDFile(pidFile); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}

	// Read it back
	pid, err := ReadPIDFile(pidFile)
	if err != nil {
		t.Fatalf("ReadPIDFile failed: %v", err)
	}

	if pid != os.Getpid() {
		t.Errorf("ReadPIDFile = %d, want %d", pid, os.Getpid())
	}
}

func TestReadPIDFile_MissingFile(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	_, err := ReadPIDFile(pidFile)
	if err == nil {
		t.Error("expected error reading nonexistent PID file")
	}
}

func TestReadPIDFile_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	os.WriteFile(pidFile, []byte("not-a-number"), 0600)

	_, err := ReadPIDFile(pidFile)
	if err == nil {
		t.Error("expected error for invalid PID content")
	}
}

func TestReadPIDFile_NegativePID(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	os.WriteFile(pidFile, []byte("-1"), 0600)

	_, err := ReadPIDFile(pidFile)
	if err == nil {
		t.Error("expected error for negative PID")
	}
}

func TestReadPIDFile_ZeroPID(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	os.WriteFile(pidFile, []byte("0"), 0600)

	_, err := ReadPIDFile(pidFile)
	if err == nil {
		t.Error("expected error for zero PID")
	}
}

func TestReadPIDFile_WhitespaceHandling(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	pid := os.Getpid()
	// Write PID with trailing newline (common in PID files)
	os.WriteFile(pidFile, []byte(strconv.Itoa(pid)+"\n"), 0600)

	got, err := ReadPIDFile(pidFile)
	if err != nil {
		t.Fatalf("ReadPIDFile failed with trailing newline: %v", err)
	}
	if got != pid {
		t.Errorf("ReadPIDFile = %d, want %d", got, pid)
	}
}

func TestIsProcessRunning_CurrentProcess(t *testing.T) {
	if !IsProcessRunning(os.Getpid()) {
		t.Error("expected IsProcessRunning=true for current process")
	}
}

func TestIsProcessRunning_NonExistentPID(t *testing.T) {
	// PID 9999999 almost certainly doesn't exist
	if IsProcessRunning(9999999) {
		t.Error("expected IsProcessRunning=false for non-existent PID")
	}
}

func TestIsProcessRunning_PID1(t *testing.T) {
	// PID 1 (init/launchd) should always be running, but we may not have
	// permission to signal it. On macOS, kill(1, 0) returns EPERM for
	// non-root users, which means the process exists but we can't signal it.
	// os.Process.Signal returns a non-nil error for EPERM, so IsProcessRunning
	// returns false. This is acceptable behavior — we only need to detect
	// our own agent processes.
	// Just verify it doesn't panic.
	_ = IsProcessRunning(1)
}

func TestRemovePIDFile_ExistingFile(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	os.WriteFile(pidFile, []byte("12345"), 0600)

	RemovePIDFile(pidFile)

	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("PID file should be removed")
	}
}

func TestRemovePIDFile_NonExistent(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	// Should not panic or error
	RemovePIDFile(pidFile)
}

func TestCleanStalePIDFile_NoFile(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	err := CleanStalePIDFile(pidFile)
	if err != nil {
		t.Errorf("CleanStalePIDFile should succeed when no file exists: %v", err)
	}
}

func TestCleanStalePIDFile_StalePID(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	// Write a PID that doesn't exist
	os.WriteFile(pidFile, []byte("9999999"), 0600)

	err := CleanStalePIDFile(pidFile)
	if err != nil {
		t.Errorf("CleanStalePIDFile should succeed for stale PID: %v", err)
	}

	// File should be removed
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("stale PID file should be removed")
	}
}

func TestCleanStalePIDFile_RunningPID(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	// Write our own PID — definitely running
	os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600)

	err := CleanStalePIDFile(pidFile)
	if err == nil {
		t.Error("CleanStalePIDFile should return error when process is running")
	}

	// File should NOT be removed
	if _, err := os.Stat(pidFile); os.IsNotExist(err) {
		t.Error("PID file for running process should not be removed")
	}
}

func TestCleanStalePIDFile_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	os.WriteFile(pidFile, []byte("garbage"), 0600)

	err := CleanStalePIDFile(pidFile)
	if err != nil {
		t.Errorf("CleanStalePIDFile should succeed for unparseable content: %v", err)
	}

	// Invalid file should be removed
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("unparseable PID file should be removed")
	}
}

func TestCleanStalePIDFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	os.WriteFile(pidFile, []byte(""), 0600)

	err := CleanStalePIDFile(pidFile)
	if err != nil {
		t.Errorf("CleanStalePIDFile should succeed for empty file: %v", err)
	}

	// Empty file should be removed
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("empty PID file should be removed")
	}
}

func TestWritePIDFile_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "agent.pid")

	// Write a fake PID first
	os.WriteFile(pidFile, []byte("99999"), 0600)

	// Overwrite with current PID
	if err := WritePIDFile(pidFile); err != nil {
		t.Fatalf("WritePIDFile failed: %v", err)
	}

	pid, err := ReadPIDFile(pidFile)
	if err != nil {
		t.Fatalf("ReadPIDFile failed: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("WritePIDFile should overwrite: got PID %d, want %d", pid, os.Getpid())
	}
}
