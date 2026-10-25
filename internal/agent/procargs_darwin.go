package agent

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// readProcArgs returns the argv of the process with the given PID, as
// reported by `ps -o args=`. The output is split on whitespace, so an
// argument containing spaces comes back as several elements.
func readProcArgs(pid int) ([]string, error) {
	out, err := exec.Command("ps", "-o", "args=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return nil, fmt.Errorf("ps args of PID %d: %w", pid, err)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil, fmt.Errorf("empty ps args for PID %d", pid)
	}
	return strings.Fields(trimmed), nil
}
