package agent

import (
	"os"
	"strconv"
	"strings"
)

// caffeinateArgs builds the macOS `caffeinate` arguments. `-i` inhibits idle
// system sleep; `-w <pid>` makes caffeinate self-exit when the agent process
// ends, so the assertion is released even if the agent dies without a clean
// context cancel (panic, SIGKILL).
func caffeinateArgs(pid int) []string {
	return []string{"-i", "-w", strconv.Itoa(pid)}
}

// isWSL reports whether the given /proc/version contents indicate the Linux
// kernel is running under the Windows Subsystem for Linux. Both WSL1
// ("Microsoft") and WSL2 ("microsoft-standard-WSL2") carry the marker.
func isWSL(procVersion string) bool {
	return strings.Contains(strings.ToLower(procVersion), "microsoft")
}

// readProcVersion returns the contents of /proc/version, or "" if unreadable.
func readProcVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return ""
	}
	return string(data)
}
