package agent

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// readProcArgs returns the argv of the process with the given PID, read from
// /proc/<pid>/cmdline (NUL-separated, with a trailing NUL).
func readProcArgs(pid int) ([]string, error) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return nil, fmt.Errorf("read cmdline of PID %d: %w", pid, err)
	}
	trimmed := strings.TrimSuffix(string(data), "\x00")
	if trimmed == "" {
		return nil, fmt.Errorf("empty cmdline for PID %d", pid)
	}
	return strings.Split(trimmed, "\x00"), nil
}
