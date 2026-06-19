package agent

import (
	"errors"
	"fmt"
	"io"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

// Indirected through package vars so tests can exercise the stop-failure
// short-circuit without inducing a real signal-permission error.
var (
	runAgentStop  = RunAgentStop
	runAgentStart = RunAgentStart
)

// RunAgentRestart stops the agent (if running) and starts it again — the
// functional equivalent of `pmux agent stop` followed by `pmux agent start`.
//
// Two deliberate simplifications over running the two commands literally:
//   - A restart when nothing is running is not an error; it just starts the
//     agent (a bare `stop` exits non-zero in that case).
//   - No extra wait between the phases: RunAgentStop is synchronous and removes
//     the PID file before returning, and RunAgentStart's spawn is gated on
//     reading that file — so the start phase always spawns fresh with no
//     stale-PID race. If stop fails outright, start is not attempted (the old
//     process may still be alive).
func RunAgentRestart(paths config.Paths, store auth.SecretStore, w io.Writer) error {
	switch err := runAgentStop(paths, w); {
	case err == nil:
		// Stopped, or a stale PID file was cleaned up.
	case errors.Is(err, ErrAgentNotRunning):
		fmt.Fprintln(w, "Agent was not running")
	default:
		return err
	}
	return runAgentStart(paths, store, w)
}
