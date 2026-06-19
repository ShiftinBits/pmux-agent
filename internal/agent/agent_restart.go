package agent

import (
	"errors"
	"fmt"
	"io"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

// RunAgentRestart stops the agent (if running) and starts it again — the
// functional equivalent of `pmux agent stop` followed by `pmux agent start`.
//
// Two deliberate simplifications over running the two commands literally:
//   - A restart when nothing is running is not an error; it just starts the
//     agent (a bare `stop` exits non-zero in that case).
//   - No extra wait between the phases: RunAgentStop is synchronous — it blocks
//     until the process exits and removes the PID file — so the start phase
//     always spawns a fresh process with no stale-PID race.
func RunAgentRestart(paths config.Paths, store auth.SecretStore, w io.Writer) error {
	switch err := RunAgentStop(paths, w); {
	case err == nil:
		// Stopped, or a stale PID file was cleaned up.
	case errors.Is(err, ErrAgentNotRunning):
		fmt.Fprintln(w, "Agent is not running")
	default:
		return err
	}
	return RunAgentStart(paths, store, w)
}
