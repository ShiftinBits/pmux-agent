//go:build windows

package firewall

import (
	"fmt"
	"os"
	"strings"
)

// isElevated reports whether the process has an elevated (admin) token.
// Opening this device succeeds only for elevated processes.
func isElevated() bool {
	f, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err == nil {
		f.Close()
		return true
	}
	return false
}

// relaunchElevated re-launches self with args via a UAC prompt, waiting for it.
func relaunchElevated(self string, args []string) error {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", "''") + "'"
	}
	argList := strings.Join(quoted, ",")
	ps := fmt.Sprintf(
		"Start-Process -FilePath '%s' -ArgumentList %s -Verb RunAs -Wait",
		strings.ReplaceAll(self, "'", "''"), argList)
	cmd := execCommand("powershell", "-NonInteractive", "-Command", ps)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
