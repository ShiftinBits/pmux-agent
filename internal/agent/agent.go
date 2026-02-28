// Package agent implements the core PocketMux agent lifecycle: start, connect, shutdown.
package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
	"github.com/shiftinbits/pmux-agent/internal/webrtc"
)

const (
	// tmuxStartTimeout is how long the agent waits for the tmux server to start.
	tmuxStartTimeout = 30 * time.Second
	// tmuxPollInterval is how often the agent checks if the tmux server is alive.
	tmuxPollInterval = 2 * time.Second
	// tmuxGracePeriod is how long the agent waits for the tmux server to reappear
	// before shutting down. A user might kill the last session and immediately
	// create a new one.
	tmuxGracePeriod = 5 * time.Second
	// tmuxGracePollInterval is how often the agent checks during the grace period.
	tmuxGracePollInterval = 1 * time.Second
	// tmuxStartPollInterval is how often the agent polls while waiting for the
	// tmux server to appear on startup.
	tmuxStartPollInterval = 1 * time.Second
)

// serverChecker abstracts tmux server liveness checks for testability.
type serverChecker interface {
	IsServerRunning() bool
}

// watchConfig holds timing parameters for watchTmux. Production code uses
// the package-level constants; tests can supply shorter intervals.
type watchConfig struct {
	startTimeout time.Duration
	startPoll    time.Duration
	pollInterval time.Duration
	gracePeriod  time.Duration
	gracePoll    time.Duration
}

// defaultWatchConfig returns the production timing configuration.
func defaultWatchConfig() watchConfig {
	return watchConfig{
		startTimeout: tmuxStartTimeout,
		startPoll:    tmuxStartPollInterval,
		pollInterval: tmuxPollInterval,
		gracePeriod:  tmuxGracePeriod,
		gracePoll:    tmuxGracePollInterval,
	}
}

// Run starts the PocketMux agent. It connects to the signaling server,
// handles WebRTC connections, and monitors the tmux server.
// Blocks until the context is canceled or the tmux server exits.
func Run(ctx context.Context, paths config.Paths) error {
	// Set up file logging
	logFile := filepath.Join(paths.ConfigDir, "host.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer f.Close()

	logger := slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	logger.Info("host starting", "pid", os.Getpid())

	// Write our own PID file (overwrites the one written by spawn with the
	// actual agent PID — they match in practice, but this ensures correctness).
	pidFile := PIDFilePath(paths)
	if err := WritePIDFile(pidFile); err != nil {
		logger.Error("failed to write PID file", "error", err)
		// Non-fatal: agent can still run, just harder to manage
	}

	// Load config for server URL, socket name, and timing settings
	cfg, err := config.LoadConfig(paths.ConfigFile)
	if err != nil {
		logger.Warn("failed to load config, using defaults", "error", err)
		cfg = config.Defaults()
	}

	// Create secret store for secure key storage
	store, err := auth.NewSecretStore(paths.KeysDir, cfg.Identity.SecretBackend)
	if err != nil {
		return fmt.Errorf("initialize secret store: %w", err)
	}
	logger.Info("secret store initialized", "backend", store.Backend())

	// Load identity
	identity, err := auth.LoadIdentity(paths.KeysDir, store)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	logger.Info("identity loaded", "deviceID", identity.DeviceID)

	// Create tmux client targeting the configured socket
	tmuxClient := tmux.NewClient(cfg.Tmux.SocketName)

	serverURL := cfg.ServerURL()

	// Create components with forward references (resolved via closures)
	var peerManager *webrtc.PeerManager

	handler := NewHandler(tmuxClient, func(peerID string, msg protocol.Message) error {
		return peerManager.SendTo(peerID, msg)
	}, func(data []byte) {
		peerManager.BroadcastRaw(data)
	}, logger)

	signalingClient := webrtc.NewSignalingClient(identity, serverURL, func(msg webrtc.SignalingMessage) {
		peerManager.HandleSignalingMessage(msg)
	}, logger)
	signalingClient.PresenceInterval = cfg.KeepaliveInterval()

	peerManager = webrtc.NewPeerManager(
		logger,
		signalingClient,
		serverURL,
		signalingClient.JWT,
		handler.HandleMessage,
	)
	peerManager.MaxPeers = cfg.Connection.MaxMobileConnections

	// Load paired device for connection validation
	pairedDevicesPath := filepath.Join(paths.ConfigDir, "paired_devices.json")
	pairedDevice, err := auth.LoadPairedDevice(pairedDevicesPath, store)
	if err == nil && pairedDevice != nil {
		peerManager.AllowedDeviceID = pairedDevice.DeviceID
	}

	// Create a cancelable context for the agent
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle SIGUSR1 to wake signaling client from dormancy.
	// The supervisor sends SIGUSR1 on every pmux CLI invocation so that a
	// dormant agent resumes reconnection without requiring a manual restart.
	usr1Ch := make(chan os.Signal, 1)
	signal.Notify(usr1Ch, syscall.SIGUSR1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				signal.Stop(usr1Ch)
				return
			case <-usr1Ch:
				logger.Info("SIGUSR1 received, signaling activity")
				signalingClient.SignalActivity()
			}
		}
	}()

	// Watch for tmux server lifecycle (tmux.Client satisfies serverChecker)
	go watchTmux(ctx, cancel, tmuxClient, handler.BroadcastEmptySessions, defaultWatchConfig(), logger)

	// Start connection cleaner to detect and close idle peers (no ping in 60s)
	cleaner := NewConnectionCleaner(handler, peerManager, logger)
	go cleaner.Run(ctx)

	// Run signaling client (blocks until context is canceled)
	logger.Info("connecting to signaling server", "url", serverURL)
	err = signalingClient.Run(ctx)

	// Cleanup
	logger.Info("host shutting down")
	peerManager.CloseAll()
	signalingClient.Close()
	RemovePIDFile(pidFile)

	if err != nil && err != context.Canceled {
		return err
	}
	return nil
}

// watchTmux monitors the tmux server on the pmux socket.
// It waits for the server to start, then monitors until it exits.
// When the tmux server exits, a 5-second grace period begins (the user may
// immediately create a new session). If the server reappears, normal monitoring
// resumes. If the grace period expires, onGraceExpired is called (to notify
// connected mobile clients) and the agent context is canceled.
func watchTmux(ctx context.Context, cancel context.CancelFunc, tc serverChecker, onGraceExpired func(), cfg watchConfig, logger *slog.Logger) {
	ticker := time.NewTicker(cfg.startPoll)
	defer ticker.Stop()

	// Wait for tmux server to start (it may start after the agent)
	startDeadline := time.After(cfg.startTimeout)
	started := false
	for !started {
		select {
		case <-ctx.Done():
			return
		case <-startDeadline:
			logger.Warn("tmux server did not start within timeout, shutting down")
			cancel()
			return
		case <-ticker.C:
			if tc.IsServerRunning() {
				started = true
				logger.Info("tmux server detected")
			}
		}
	}

	// Stop the startup ticker before switching to monitoring interval
	ticker.Stop()

	// Monitor for tmux server exit
	monitorTicker := time.NewTicker(cfg.pollInterval)
	defer monitorTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-monitorTicker.C:
			if !tc.IsServerRunning() {
				logger.Info("tmux server exited, starting grace period",
					"grace", cfg.gracePeriod.String())

				if gracePeriodExpired(ctx, tc, cfg, logger) {
					logger.Info("grace period expired, shutting down host")
					onGraceExpired()
					cancel()
					return
				}

				// Server reappeared during grace period
				logger.Info("tmux server reappeared, resuming monitoring")
			}
		}
	}
}

// gracePeriodExpired polls for the tmux server at a faster interval during
// the grace period. Returns true if the grace period expired without the
// server reappearing; false if the server came back or the context was canceled.
func gracePeriodExpired(ctx context.Context, tc serverChecker, cfg watchConfig, logger *slog.Logger) bool {
	graceTicker := time.NewTicker(cfg.gracePoll)
	defer graceTicker.Stop()

	deadline := time.After(cfg.gracePeriod)

	for {
		select {
		case <-ctx.Done():
			return false
		case <-deadline:
			return true
		case <-graceTicker.C:
			if tc.IsServerRunning() {
				return false
			}
			logger.Debug("grace period: tmux server still gone")
		}
	}
}
