package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

// WritePIDFile writes the current process PID to the given path atomically.
// Uses write-to-tmp + rename to prevent partial reads by concurrent processes.
func WritePIDFile(path string) error {
	pid := os.Getpid()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(pid)), pidFilePerms); err != nil {
		return fmt.Errorf("write PID file %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return fmt.Errorf("rename PID file %s: %w", path, err)
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

// procArgs reads a process's argv. Package var so tests can fake an agent.
var procArgs = readProcArgs

// IsProcessRunning checks whether a process with the given PID is alive.
// Uses kill(pid, 0) — signal 0 does not send a signal but checks for process existence.
//
// It does not check what the process is. A PID read from agent.pid may have
// been reused by an unrelated process, so callers that signal that PID (or
// spawn based on the result) must use IsAgentProcess instead.
func IsProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

// IsAgentProcess reports whether the process with the given PID is alive and
// is a Pocketmux agent, i.e. its argv is `<...>/pmux agent run` as exec'd by
// spawn. Only the base name of argv[0] is compared: after an update the
// original executable path may be deleted or re-pointed by the package manager.
func IsAgentProcess(pid int) bool {
	if !IsProcessRunning(pid) {
		return false
	}
	argv, err := procArgs(pid)
	n := len(argv)
	if err != nil || n < 3 || argv[n-2] != "agent" || argv[n-1] != "run" {
		return false
	}
	// Match from the tail and rejoin the rest: the darwin reader splits on
	// whitespace, so an executable path with spaces arrives as several fields.
	return filepath.Base(strings.Join(argv[:n-2], " ")) == "pmux"
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
