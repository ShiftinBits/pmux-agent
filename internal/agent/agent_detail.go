package agent

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/shiftinbits/pmux-agent/internal/config"
)

// RunAgentDetail prints detailed agent status: version, PID, uptime
// (best-effort via ps), and recent log lines. This backs "pmux agent status".
//
// Returns ErrAgentNotRunning when the agent PID is missing or stale.
func RunAgentDetail(version string, paths config.Paths, w io.Writer) error {
	fmt.Fprintf(w, "pmux %s\n", version)

	pidFile := PIDFilePath(paths)

	pid, err := ReadPIDFile(pidFile)
	if err != nil {
		fmt.Fprintln(w, "Agent is not running")
		return ErrAgentNotRunning
	}

	if !IsProcessRunning(pid) {
		fmt.Fprintln(w, "Agent is not running (stale PID file)")
		CleanStalePIDFile(pidFile)
		return ErrAgentNotRunning
	}

	fmt.Fprintf(w, "Agent is running (PID %d)\n", pid)

	// Try to get process uptime via ps (best-effort, errors silently ignored)
	out, err := exec.Command("ps", "-o", "etime=", "-p", fmt.Sprintf("%d", pid)).Output()
	if err == nil {
		uptime := strings.TrimSpace(string(out))
		if uptime != "" {
			fmt.Fprintf(w, "Uptime: %s\n", uptime)
		}
	}

	// Show last 5 lines of agent log
	logFile := filepath.Join(paths.ConfigDir, "agent.log")
	lines, err := tailFile(logFile, 5)
	if err == nil && len(lines) > 0 {
		fmt.Fprintln(w, "\nRecent log:")
		for _, line := range lines {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}

	return nil
}

// tailFile reads the last n lines from a file.
func tailFile(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > n {
			lines = lines[1:]
		}
	}
	return lines, scanner.Err()
}
