package agent

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

const (
	// pidFileName is the name of the PID file within the config directory.
	pidFileName = "agent.pid"
	// pidFilePerms is the file permission mode for the PID file (owner read/write only).
	pidFilePerms = 0600
)

// WritePIDFile writes the current process PID to the given path with 0600 permissions.
func WritePIDFile(path string) error {
	pid := os.Getpid()
	if err := os.WriteFile(path, []byte(strconv.Itoa(pid)), pidFilePerms); err != nil {
		return fmt.Errorf("write PID file %s: %w", path, err)
	}
	return nil
}

// ReadPIDFile reads and parses the PID from the given file path.
// Returns the PID value or an error if the file cannot be read or parsed.
func ReadPIDFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read PID file %s: %w", path, err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse PID from %s: %w", path, err)
	}

	if pid <= 0 {
		return 0, fmt.Errorf("invalid PID %d in %s", pid, path)
	}

	return pid, nil
}

// IsProcessRunning checks whether a process with the given PID is alive.
// Uses kill(pid, 0) — signal 0 does not send a signal but checks for process existence.
func IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// RemovePIDFile removes the PID file at the given path.
// This is best-effort: errors are silently ignored (e.g., file already removed).
func RemovePIDFile(path string) {
	os.Remove(path) //nolint:errcheck
}

// CleanStalePIDFile reads the PID file, checks if the process is still running,
// and removes the file if the process is no longer alive (stale PID).
// Returns nil if the file was cleaned up or didn't exist.
// Returns an error only if the PID file exists and the process is still running.
func CleanStalePIDFile(path string) error {
	pid, err := ReadPIDFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File doesn't exist — nothing to clean
			return nil
		}
		// Unparseable PID file — remove it
		RemovePIDFile(path)
		return nil
	}

	if IsProcessRunning(pid) {
		return fmt.Errorf("agent is still running (PID %d)", pid)
	}

	// Process is not running — stale PID file, remove it
	RemovePIDFile(path)
	return nil
}
