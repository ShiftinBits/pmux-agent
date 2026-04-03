package agent

import (
	"context"
	"log/slog"
	"time"
)

const (
	// DefaultCleanupInterval is how often the cleaner scans for stale peers.
	DefaultCleanupInterval = 30 * time.Second

	// DefaultIdleTimeout is how long a peer can go without sending a ping
	// before being considered stale and closed.
	DefaultIdleTimeout = 60 * time.Second
)

// PeerCloser closes a specific peer connection by device ID.
type PeerCloser interface {
	ClosePeer(deviceID string)
}

// PeerStateChecker provides PeerConnection state information for safety-net
// cleanup. The ConnectionCleaner uses this to detect peers stuck in failed
// or closed state that weren't cleaned up by the primary state handlers.
type PeerStateChecker interface {
	PeerStates() map[string]string
}

// ConnectionCleaner periodically scans for idle peers and closes them.
// A peer is considered idle if it has not sent a ping within the configured
// timeout (default: 60s). The cleaner runs a goroutine that ticks at the
// configured interval (default: 30s).
//
// When a PeerStateChecker is configured (via WithStateChecker), the cleaner
// also closes peers whose PeerConnection is in "failed" or "closed" state
// as a safety net for the primary state change handlers.
type ConnectionCleaner struct {
	handler      *Handler
	closer       PeerCloser
	stateChecker PeerStateChecker
	interval     time.Duration
	timeout      time.Duration
	logger       *slog.Logger
}

// NewConnectionCleaner creates a ConnectionCleaner with default timing.
func NewConnectionCleaner(handler *Handler, closer PeerCloser, logger *slog.Logger) *ConnectionCleaner {
	return &ConnectionCleaner{
		handler:  handler,
		closer:   closer,
		interval: DefaultCleanupInterval,
		timeout:  DefaultIdleTimeout,
		logger:   logger,
	}
}

// WithInterval sets a custom scan interval (for testing).
func (cc *ConnectionCleaner) WithInterval(d time.Duration) *ConnectionCleaner {
	cc.interval = d
	return cc
}

// WithTimeout sets a custom idle timeout (for testing).
func (cc *ConnectionCleaner) WithTimeout(d time.Duration) *ConnectionCleaner {
	cc.timeout = d
	return cc
}

// WithStateChecker sets a PeerStateChecker for safety-net cleanup.
// When set, sweep() also closes peers whose PeerConnection is in
// "failed" or "closed" state.
func (cc *ConnectionCleaner) WithStateChecker(sc PeerStateChecker) *ConnectionCleaner {
	cc.stateChecker = sc
	return cc
}

// Run starts the cleanup loop. Blocks until the context is canceled.
func (cc *ConnectionCleaner) Run(ctx context.Context) {
	ticker := time.NewTicker(cc.interval)
	defer ticker.Stop()

	cc.logger.Debug("connection cleaner started",
		"interval", cc.interval, "timeout", cc.timeout)

	for {
		select {
		case <-ctx.Done():
			cc.logger.Debug("connection cleaner stopped")
			return
		case <-ticker.C:
			cc.sweep()
		}
	}
}

// sweep checks for stale peers and closes them. When a PeerStateChecker
// is configured, it also closes peers whose PeerConnection is in "failed"
// or "closed" state as a safety net.
func (cc *ConnectionCleaner) sweep() {
	// Close peers that haven't pinged within the timeout.
	stale := cc.handler.GetStalePeers(cc.timeout)
	for _, peerID := range stale {
		cc.logger.Info("closing idle peer", "peer", peerID, "timeout", cc.timeout)
		func() {
			defer func() {
				if r := recover(); r != nil {
					cc.logger.Error("panic in PeerDisconnected during sweep",
						"recover", r, "peer", peerID)
				}
			}()
			cc.handler.PeerDisconnected(peerID)
		}()
		cc.closer.ClosePeer(peerID)
	}

	// Safety net: close peers with dead PeerConnection state.
	// The primary state change handlers (handlePeerStateChange) should handle
	// these transitions, but this catches any that slip through.
	if cc.stateChecker != nil {
		// Build a set of already-closed peers to avoid double-closing.
		closedSet := make(map[string]bool, len(stale))
		for _, peerID := range stale {
			closedSet[peerID] = true
		}

		for peerID, state := range cc.stateChecker.PeerStates() {
			if closedSet[peerID] {
				continue
			}
			if state == "failed" || state == "closed" {
				cc.logger.Info("closing peer with dead PC state (safety net)",
					"peer", peerID, "pcState", state)
				func() {
					defer func() {
						if r := recover(); r != nil {
							cc.logger.Error("panic in PeerDisconnected during sweep",
								"recover", r, "peer", peerID)
						}
					}()
					cc.handler.PeerDisconnected(peerID)
				}()
				cc.closer.ClosePeer(peerID)
			}
		}
	}
}
