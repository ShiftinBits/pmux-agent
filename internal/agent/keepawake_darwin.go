package agent

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
)

// startKeepAwake inhibits idle system sleep on macOS by holding a `caffeinate`
// child process bound to ctx. caffeinate registers an IOKit power assertion
// with powerd that is automatically released when it exits — there is no
// persistent power setting to save or restore.
//
// Best-effort: this does NOT override closing the laptop lid (clamshell sleep)
// or a forced sleep on critically low battery — those are OS power-policy
// decisions no userspace assertion can veto.
func startKeepAwake(ctx context.Context, logger *slog.Logger) {
	// Absolute path: caffeinate is a fixed, SIP-protected system binary, and a
	// background agent may not inherit the user's interactive PATH.
	cmd := exec.CommandContext(ctx, "/usr/bin/caffeinate", caffeinateArgs(os.Getpid())...)
	if err := cmd.Start(); err != nil {
		logger.Warn("keep_awake: failed to start caffeinate", "error", err)
		return
	}
	logger.Info("keep_awake enabled: holding caffeinate idle-sleep assertion", "inhibitorPid", cmd.Process.Pid)

	// Reap the child when it exits (ctx cancel or external kill) so it doesn't
	// linger as a zombie.
	go func() {
		if err := cmd.Wait(); err != nil && ctx.Err() == nil {
			logger.Warn("keep_awake: caffeinate exited unexpectedly", "error", err)
		}
	}()
}
