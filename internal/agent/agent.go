// Package agent implements the core Pocketmux agent lifecycle: start, connect, shutdown.
package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/firewall"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
	"github.com/shiftinbits/pmux-agent/internal/update"
	"github.com/shiftinbits/pmux-agent/internal/webrtc"
)

// FatalInitError wraps errors that won't self-resolve on a fresh spawn,
// such as missing identity, corrupt config, or secret store failures.
// These should cause the agent to exit without being treated as retryable.
type FatalInitError struct {
	Err error
}

func (e *FatalInitError) Error() string { return e.Err.Error() }
func (e *FatalInitError) Unwrap() error { return e.Err }

// IsFatalInitError reports whether err is a FatalInitError.
func IsFatalInitError(err error) bool {
	var fatal *FatalInitError
	return errors.As(err, &fatal)
}

// serverChecker abstracts tmux server liveness checks for testability.
type serverChecker interface {
	IsServerRunning() bool
}

const (
	// maxLogSize is the threshold at which agent.log is rotated.
	// When the file exceeds this size on startup, it is renamed to agent.log.1
	// and a fresh agent.log is opened. Only one backup is kept.
	maxLogSize = 10 * 1024 * 1024 // 10 MiB
)

// rotateLogIfNeeded renames logPath to logPath+".1" when the file exceeds
// maxLogSize, making room for a fresh log on the next open. Errors are
// silently ignored — logging must not block agent startup.
func rotateLogIfNeeded(logPath string) {
	info, err := os.Stat(logPath)
	if err != nil || info.Size() < maxLogSize {
		return
	}
	os.Rename(logPath, logPath+".1") //nolint:errcheck
}

// Run starts the Pocketmux agent. It connects to the signaling server,
// handles WebRTC connections, and monitors the tmux server.
// Blocks until the context is canceled (SIGTERM/SIGINT or fatal error).
func Run(ctx context.Context, paths config.Paths, hmacSecret, version, installMethod string) error {
	// Set up file logging with size-based rotation.
	logFile := filepath.Join(paths.ConfigDir, "agent.log")
	rotateLogIfNeeded(logFile)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	logLevel := &slog.LevelVar{}
	logLevel.Set(slog.LevelInfo) // safe default until config is loaded
	logger := slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{
		Level: logLevel,
	}))

	// Write our own PID file (overwrites the one written by spawn with the
	// actual agent PID — they match in practice, but this ensures correctness).
	pidFile := PIDFilePath(paths)
	if err := WritePIDFile(pidFile); err != nil {
		logger.Error("failed to write PID file", "error", err)
		// Non-fatal: agent can still run, just harder to manage
	}

	// Register SIGUSR1 handler early — before any initialization that could
	// delay startup. The channel is buffered so signals received before the
	// goroutine starts reading are not lost.
	usr1Ch := make(chan os.Signal, 1)
	signal.Notify(usr1Ch, syscall.SIGUSR1)

	usr2Ch := make(chan os.Signal, 1)
	signal.Notify(usr2Ch, syscall.SIGUSR2)

	// Load config for server URL, socket name, and timing settings
	cfg, err := config.LoadConfig(paths.ConfigFile)
	if err != nil {
		logger.Warn("failed to load config, using defaults", "error", err)
		cfg = config.Defaults()
	}

	// Apply configured log level (default: info)
	logLevel.Set(cfg.ParseLogLevel())
	logger.Info("agent starting", "pid", os.Getpid(), "logLevel", cfg.LogLevel)

	// Create secret store for secure key storage
	store, err := auth.NewSecretStore(paths.KeysDir, cfg.Identity.SecretBackend, logger)
	if err != nil {
		return &FatalInitError{Err: fmt.Errorf("initialize secret store: %w", err)}
	}
	logger.Info("secret store initialized", "backend", store.Backend())

	// Load identity
	identity, err := auth.LoadIdentity(paths.KeysDir, store, logger)
	if err != nil {
		return &FatalInitError{Err: fmt.Errorf("load identity: %w", err)}
	}
	logger.Info("identity loaded", "deviceID", identity.DeviceID)

	// Best-effort: warn if the host firewall is likely blocking inbound
	// connections to this binary. Detection-only — the mobile app falls back to
	// a TURN relay when a direct connection can't form. Never fatal.
	if exePath, errFW := firewall.ExecutablePath(); errFW == nil {
		if st := firewall.NewManager().Probe(exePath); firewall.NeedsAttention(st) {
			logger.Warn(firewall.Warning)
		}
	}

	// Create tmux client targeting the configured socket.
	// Use the configured tmux path (resolved at init time) so the agent works
	// when PATH is minimal (e.g., when spawned non-interactively).
	tmuxClient := tmux.NewClient(cfg.Tmux.SocketName)
	if cfg.Tmux.TmuxPath != "" {
		tmuxClient.TmuxBin = cfg.Tmux.TmuxPath
	}

	// Suppress zsh's PROMPT_EOL_MARK in pmux sessions. When terminal output
	// doesn't end with a newline, zsh renders a '%' marker with inverse video.
	// On the host terminal this is transient, but through pipe-pane streaming
	// to the mobile app the marker persists visibly. Setting it empty disables
	// the marker for all new panes on the pmux socket.
	if err := tmuxClient.SetGlobalEnv("PROMPT_EOL_MARK", ""); err != nil {
		logger.Debug("failed to set PROMPT_EOL_MARK (tmux server may not be running yet)", "error", err)
	}

	// apiBaseURL carries the configured API version suffix (e.g. ".../v1")
	// so every HTTP/WS call made via the signaling client and peer manager
	// picks up the prefix automatically. Raw cfg.ServerURL() is still used
	// for logging and any user-facing display.
	apiBaseURL := cfg.APIBaseURL()

	// Create components with forward references (resolved via closures)
	var peerManager *webrtc.PeerManager

	updateStateFile := update.StateFilePath(paths.ConfigDir)

	handler := NewHandler(tmuxClient, func(peerID string, msg protocol.Message) error {
		return peerManager.SendTo(peerID, msg)
	}, logger, version, updateStateFile)

	hostName := cfg.Name
	if hostName == "" {
		hostName = config.DefaultHostName()
	}
	signalingClient := webrtc.NewSignalingClient(identity, apiBaseURL, hostName, func(msg webrtc.SignalingMessage) {
		if msg.Type == "mobile_name_updated" && msg.DeviceID != "" && msg.Name != "" {
			// Only accept name updates for the currently paired device.
			if allowedID := peerManager.AllowedDeviceID(); allowedID == "" || msg.DeviceID != allowedID {
				logger.Debug("ignoring mobile_name_updated for non-paired device",
					"deviceId", msg.DeviceID, "expected", allowedID)
				return
			}
			truncatedName := auth.TruncateMobileName(msg.Name)
			updated, err := auth.UpdatePairedDeviceName(paths.PairedDevices, store, msg.DeviceID, truncatedName)
			if err != nil {
				logger.Warn("failed to update mobile device name", "error", err)
			} else if updated {
				logger.Debug("updated paired mobile device name", "deviceId", msg.DeviceID, "name", truncatedName)
			}
			return
		}
		peerManager.HandleSignalingMessage(msg)
	}, logger, hmacSecret)
	signalingClient.PresenceInterval = cfg.KeepaliveInterval()
	signalingClient.InitialBackoff = cfg.ReconnectInterval()

	peerManager = webrtc.NewPeerManager(
		logger,
		signalingClient,
		apiBaseURL,
		signalingClient.JWT,
		handler.HandleMessage,
		hmacSecret,
	)
	peerManager.MaxPeers = cfg.Connection.MaxMobileConnections
	peerManager.ForceRelay = cfg.Connection.ForceRelay
	peerManager.OnPeerDisconnect = handler.PeerDisconnected
	// Verify connect-time key possession (SB-992): resolve the paired device's
	// X25519 shared secret from the secure store so the agent can authenticate
	// the peer independently of the (untrusted) signaling server.
	peerManager.SharedSecretFn = func(deviceID string) ([]byte, error) {
		return store.Get(auth.SharedSecretKey(deviceID))
	}

	// Load paired device for connection validation.
	// On error (corrupt file, decryption failure), reject all connections
	// rather than falling through with an empty allowedDeviceID (which would
	// allow any device to connect).
	pairedDevice, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		logger.Warn("failed to load paired device, rejecting all connections", "error", err)
		peerManager.SetAllowedDeviceID("!invalid-load-error")
	} else if pairedDevice != nil {
		peerManager.SetAllowedDeviceID(pairedDevice.DeviceID)
	} else {
		// Unpaired (LoadPairedDevice returned nil, nil): set an explicit sentinel
		// so the guard fails closed and rejects any device until pairing completes.
		peerManager.SetAllowedDeviceID("!unpaired")
	}

	// Create a cancelable context for the agent
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Propagate agent context to handler so per-peer contexts are canceled on shutdown.
	handler.SetContext(ctx)

	// Optionally inhibit host sleep so the mobile can reach this host on demand.
	// A sleeping machine drops its signaling connection and the host shows
	// offline. Tied to ctx — the inhibitor is released on agent shutdown.
	if cfg.Power.KeepAwake {
		startKeepAwake(ctx, logger)
	}

	// Proactively mark the host offline the instant it is about to sleep, so
	// presence is accurate immediately instead of after the server's idle
	// timeout. This runs independently of keep_awake: when keep_awake is
	// successfully blocking sleep this never fires; when sleep happens anyway
	// (keep_awake off, lid close, low battery) it kicks in as the safety net.
	// Linux-only today; a no-op on other platforms.
	startSleepWatcher(ctx, logger, signalingClient.Suspend, signalingClient.Resume)

	// Handle SIGUSR1 to wake signaling client from dormancy.
	// The supervisor sends SIGUSR1 on every pmux CLI invocation so that a
	// dormant agent resumes reconnection without requiring a manual restart.
	// (usr1Ch was registered early, right after PID file write, so no signals are lost.)
	go func() {
		for {
			select {
			case <-ctx.Done():
				signal.Stop(usr1Ch)
				signal.Stop(usr2Ch)
				return
			case <-usr1Ch:
				logger.Info("SIGUSR1 received, signaling activity")
				signalingClient.SignalActivity()
			case <-usr2Ch:
				logger.Info("SIGUSR2 received, reloading pairing state")
				device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
				if err != nil {
					logger.Warn("failed to reload paired device, rejecting all connections", "error", err)
					peerManager.SetAllowedDeviceID("!invalid-load-error")
					peerManager.CloseAll()
				} else if device == nil {
					peerManager.SetAllowedDeviceID("!unpaired")
					peerManager.CloseAll()
					logger.Info("unpair complete: all peers closed")
				} else {
					peerManager.SetAllowedDeviceID(device.DeviceID)
					peerManager.CloseAll()
					logger.Info("pairing reloaded, peers closed for re-auth", "device", device.DeviceID)
				}
			}
		}
	}()

	// Monitor tmux server state (does not shut down the agent — just tracks state).
	// The callback is currently unused; a future version may propagate state to mobile.
	go monitorTmux(ctx, tmuxClient, func(bool) {}, tmuxMonitorInterval, logger)

	// Start connection cleaner to detect and close idle peers (no ping in 60s).
	// WithStateChecker adds a safety-net sweep that also closes peers with
	// failed/closed PeerConnection state.
	cleaner := NewConnectionCleaner(handler, peerManager, logger).
		WithStateChecker(peerManager)
	go cleaner.Run(ctx)

	// Start periodic update checker if enabled.
	if cfg.Update.Enabled && version != "dev" {
		checker := update.NewChecker(version, updateStateFile, logger)
		method := update.Detect(installMethod)
		go runUpdateChecker(ctx, checker, method, cfg.UpdateCheckInterval(), logger)
	}

	// Run signaling client (blocks until context is canceled)
	logger.Info("connecting to signaling server", "url", apiBaseURL)
	err = signalingClient.Run(ctx)

	// Cleanup
	logger.Info("agent shutting down")

	// Bound the shutdown sequence. If cleanup stalls (stuck Pion close,
	// slow tmux IPC), force-exit after 10 seconds.
	shutdownDone := make(chan struct{})
	go func() {
		peerManager.CloseAll()
		signalingClient.Close()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		logger.Info("shutdown complete")
	case <-time.After(10 * time.Second):
		logger.Warn("shutdown timed out after 10s, forcing exit")
	}
	RemovePIDFile(pidFile)

	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// runUpdateChecker periodically checks for updates and writes the result to disk.
// It runs as a background goroutine and never returns an error that would affect
// the agent's lifecycle.
func runUpdateChecker(ctx context.Context, checker *update.Checker, method update.InstallMethod, interval time.Duration, logger *slog.Logger) {
	// Check immediately on startup.
	if state, err := checker.Check(method); err != nil {
		logger.Warn("initial update check failed", "error", err)
	} else if state.UpdateAvailable {
		logger.Info("update available", "current", state.CurrentVersion, "latest", state.LatestVersion)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if state, err := checker.Check(method); err != nil {
				logger.Warn("periodic update check failed", "error", err)
			} else if state.UpdateAvailable {
				logger.Info("update available", "current", state.CurrentVersion, "latest", state.LatestVersion)
			}
		}
	}
}
