//go:build darwin || linux

package firewall

import (
	"os"
)

// isElevated reports whether the process is running as root.
func isElevated() bool { return os.Geteuid() == 0 }

// relaunchElevated re-execs the given self binary with args under sudo,
// inheriting stdio so the user can enter their password and see output.
func relaunchElevated(self string, args []string) error {
	cmd := execCommand("sudo", append([]string{self}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
