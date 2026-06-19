package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/godbus/dbus/v5"
)

// inhibitReason is shown in `systemd-inhibit --list` and Windows is unaware of it.
const inhibitReason = "Pocketmux agent keeping host reachable"

// startKeepAwake inhibits host sleep on Linux.
//
// Under WSL, a Linux-side inhibitor is useless — when the Windows host sleeps
// the entire WSL VM is frozen regardless — so we reach across to Windows via
// interop instead. On a normal Linux host we hold a logind inhibitor lock.
func startKeepAwake(ctx context.Context, logger *slog.Logger) {
	if isWSL(readProcVersion()) {
		startKeepAwakeWSL(ctx, logger)
		return
	}
	if err := inhibitLogind(ctx, logger); err != nil {
		logger.Warn("keep_awake: could not inhibit sleep via logind "+
			"(systemd-logind may be unavailable on this system)", "error", err)
	}
}

// inhibitLogind takes a logind "block" inhibitor lock for sleep+idle and holds
// the returned file descriptor until ctx is canceled. logind releases the lock
// automatically when the fd is closed OR when the holding process dies for any
// reason (including SIGKILL) — so there is no persistent state to restore and
// no way to leak the lock across an agent crash.
func inhibitLogind(ctx context.Context, logger *slog.Logger) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("connect system bus: %w", err)
	}

	obj := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	var fd dbus.UnixFD
	// Bound the round-trip: a stuck/unresponsive system bus must not block agent
	// startup indefinitely (inhibitLogind is called synchronously from Run()).
	// The lock is then held for the agent's lifetime via the original ctx below.
	callCtx, callCancel := context.WithTimeout(ctx, 5*time.Second)
	defer callCancel()
	call := obj.CallWithContext(callCtx, "org.freedesktop.login1.Manager.Inhibit", 0,
		"sleep:idle", "pmux", inhibitReason, "block")
	if call.Err != nil {
		conn.Close()
		return fmt.Errorf("logind Inhibit: %w", call.Err)
	}
	if err := call.Store(&fd); err != nil {
		conn.Close()
		return fmt.Errorf("read inhibitor fd: %w", err)
	}
	logger.Info("keep_awake enabled: holding logind sleep inhibitor lock")

	// Release on shutdown: closing the fd drops the lock; closing the bus
	// connection frees the D-Bus resources.
	go func() {
		<-ctx.Done()
		// fd was received from logind via SCM_RIGHTS and is solely owned by us;
		// wrap it so it's closed through the os package rather than a raw syscall.
		os.NewFile(uintptr(fd), "logind-inhibitor").Close()
		conn.Close()
		logger.Info("keep_awake: released logind sleep inhibitor lock")
	}()
	return nil
}

// startKeepAwakeWSL keeps the *Windows host* awake from inside WSL via interop,
// holding a `powershell.exe` process that calls SetThreadExecutionState. Windows
// clears the execution-state flag automatically when that process exits, so —
// as on the other platforms — there is no persistent setting to restore.
//
// Best-effort, with two unavoidable caveats: (1) if Windows interop is disabled,
// powershell.exe won't launch and the host cannot be kept awake; (2) the Linux
// PID isn't visible to Windows, so if the agent is hard-killed (SIGKILL) the
// helper can outlive it until it's killed manually or Windows restarts. A clean
// shutdown (ctx cancel) always releases it.
func startKeepAwakeWSL(ctx context.Context, logger *slog.Logger) {
	// ES_CONTINUOUS (0x80000000) | ES_SYSTEM_REQUIRED (0x00000001) = 0x80000001.
	const script = `$sig='[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint e);';` +
		`$p=Add-Type -MemberDefinition $sig -Name Power -Namespace Win32 -PassThru;` +
		`$p::SetThreadExecutionState(0x80000001);` +
		`while($true){Start-Sleep -Seconds 3600}`

	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	if err := cmd.Start(); err != nil {
		logger.Warn("keep_awake: running under WSL but could not reach Windows via interop; "+
			"the Windows host cannot be kept awake", "error", err)
		return
	}
	logger.Info("keep_awake enabled (WSL): holding Windows SetThreadExecutionState via interop",
		"inhibitorPid", cmd.Process.Pid)

	go func() {
		if err := cmd.Wait(); err != nil && ctx.Err() == nil {
			logger.Warn("keep_awake: Windows interop helper exited unexpectedly", "error", err)
		}
	}()
}
