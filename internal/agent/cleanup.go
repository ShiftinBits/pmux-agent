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

// ConnectionCleaner periodically scans for idle peers and closes them.
// A peer is considered idle if it has not sent a ping within the configured
// timeout (default: 60s). The cleaner runs a goroutine that ticks at the
// configured interval (default: 30s).
type ConnectionCleaner struct {
	handler   *Handler
	closer    PeerCloser
	interval  time.Duration
	timeout   time.Duration
	logger    *slog.Logger
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

// sweep checks for stale peers and closes them.
func (cc *ConnectionCleaner) sweep() {
	stale := cc.handler.GetStalePeers(cc.timeout)
	for _, peerID := range stale {
		cc.logger.Info("closing idle peer", "peer", peerID, "timeout", cc.timeout)
		cc.handler.PeerDisconnected(peerID)
		cc.closer.ClosePeer(peerID)
	}
}
