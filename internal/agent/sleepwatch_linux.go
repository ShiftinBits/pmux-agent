package agent

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/godbus/dbus/v5"
)

const prepareForSleepSignal = "org.freedesktop.login1.Manager.PrepareForSleep"

// startSleepWatcher subscribes to systemd-logind's PrepareForSleep signal so the
// agent can notify the signaling server right before the host sleeps (onSleep)
// and refresh presence after it wakes (onResume).
//
// It holds a logind "delay" inhibitor across each sleep transition: when
// PrepareForSleep(true) fires, onSleep runs and then the delay lock is released
// so the suspend can proceed. The delay lock is what guarantees onSleep's
// message flushes before the OS freezes the process.
//
// This is independent of, and complementary to, keep_awake. keep_awake takes a
// "block" inhibitor to PREVENT sleep, so while it is working PrepareForSleep
// never fires and this stays dormant. When sleep happens anyway — keep_awake
// off, or forced through via lid close / low battery — this makes the host's
// offline status immediate instead of waiting for the server's idle timeout.
//
// Best-effort: if logind is unavailable (no systemd) it logs and returns, and
// the server's idle sweep remains the backstop.
//
// When keepAwake is set the watcher is a no-op: keep_awake holds a "block"
// inhibitor, so logind-mediated sleeps don't happen and PrepareForSleep won't
// fire. The sleeps that can still defeat a block inhibitor are firmware/kernel
// suspends that bypass logind (e.g. a direct ACPI/critical-battery suspend),
// which also don't fire PrepareForSleep — so arming a delay inhibitor here would
// just hold an idle lock and a second bus connection for nothing. The server's
// freshness gate is the backstop for those.
func startSleepWatcher(ctx context.Context, logger *slog.Logger, keepAwake bool, onSleep, onResume func()) {
	if keepAwake {
		logger.Debug("sleep watcher skipped: keep_awake is blocking sleep")
		return
	}

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		logger.Warn("sleep watcher: cannot connect to system bus (no systemd-logind?); "+
			"relying on the server idle timeout for offline detection", "error", err)
		return
	}

	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath("/org/freedesktop/login1"),
		dbus.WithMatchInterface("org.freedesktop.login1.Manager"),
		dbus.WithMatchMember("PrepareForSleep"),
	); err != nil {
		logger.Warn("sleep watcher: cannot subscribe to PrepareForSleep", "error", err)
		conn.Close()
		return
	}

	signals := make(chan *dbus.Signal, 8)
	conn.Signal(signals)

	// Arm the initial delay inhibitor so logind waits for us before the first sleep.
	delayFd := takeSleepDelay(ctx, conn, logger)
	logger.Info("sleep watcher started: will notify the signaling server before the host sleeps")

	go func() {
		defer conn.Close()
		for {
			select {
			case <-ctx.Done():
				releaseSleepDelay(delayFd)
				return
			case sig := <-signals:
				if sig == nil || sig.Name != prepareForSleepSignal || len(sig.Body) == 0 {
					continue
				}
				goingToSleep, _ := sig.Body[0].(bool)
				if goingToSleep {
					logger.Info("host is about to sleep, marking offline")
					onSleep()
					// Release the delay lock so the suspend proceeds.
					releaseSleepDelay(delayFd)
					delayFd = -1
				} else {
					logger.Info("host resumed from sleep, refreshing presence")
					onResume()
					// Re-arm the delay inhibitor for the next sleep cycle.
					delayFd = takeSleepDelay(ctx, conn, logger)
				}
			}
		}
	}()
}

// takeSleepDelay acquires a logind "delay" inhibitor on sleep and returns its
// file descriptor, or -1 on failure (logged, non-fatal). The round-trip is
// bounded so a stuck bus can't block.
func takeSleepDelay(ctx context.Context, conn *dbus.Conn, logger *slog.Logger) int {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	obj := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	var fd dbus.UnixFD
	call := obj.CallWithContext(callCtx, "org.freedesktop.login1.Manager.Inhibit", 0,
		"sleep", "pmux", "Notify the paired mobile before the host sleeps", "delay")
	if call.Err != nil {
		logger.Warn("sleep watcher: could not take delay inhibitor; "+
			"the offline notice may not flush before sleep", "error", call.Err)
		return -1
	}
	if err := call.Store(&fd); err != nil {
		logger.Warn("sleep watcher: could not read delay inhibitor fd", "error", err)
		return -1
	}
	return int(fd)
}

// releaseSleepDelay closes a delay-inhibitor fd, dropping the lock so logind can
// proceed with the suspend. Safe to call with -1 (no lock held).
func releaseSleepDelay(fd int) {
	if fd >= 0 {
		os.NewFile(uintptr(fd), "logind-sleep-delay").Close()
	}
}
