package agent

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

// mockPeerCloser records which peers were closed.
type mockPeerCloser struct {
	mu     sync.Mutex
	closed []string
}

func (m *mockPeerCloser) ClosePeer(deviceID string) {
	m.mu.Lock()
	m.closed = append(m.closed, deviceID)
	m.mu.Unlock()
}

func (m *mockPeerCloser) getClosedPeers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]string, len(m.closed))
	copy(cp, m.closed)
	return cp
}

// testCleanupHandler creates a Handler with no tmux dependency for cleanup testing.
func testCleanupHandler() *Handler {
	tc := tmux.NewClient("pmux-cleanup-test-unused")
	return NewHandler(tc, func(peerID string, msg protocol.Message) error {
		return nil
	}, func(data []byte) {}, slog.Default())
}

func TestConnectionCleaner_IdlePeerDetectedAndClosed(t *testing.T) {
	h := testCleanupHandler()
	closer := &mockPeerCloser{}

	// Simulate a peer that pinged 90 seconds ago (stale with 60s timeout)
	h.mu.Lock()
	h.lastPingTime["stale-peer"] = time.Now().Add(-90 * time.Second)
	h.mu.Unlock()

	cleaner := NewConnectionCleaner(h, closer, slog.Default()).
		WithInterval(50 * time.Millisecond).
		WithTimeout(60 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleaner.Run(ctx)

	// Wait for at least one sweep
	time.Sleep(200 * time.Millisecond)
	cancel()

	closed := closer.getClosedPeers()
	if len(closed) == 0 {
		t.Fatal("expected stale peer to be closed")
	}
	found := false
	for _, p := range closed {
		if p == "stale-peer" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("stale-peer not found in closed peers: %v", closed)
	}

	// Verify ping time was cleaned up
	h.mu.Lock()
	_, exists := h.lastPingTime["stale-peer"]
	h.mu.Unlock()
	if exists {
		t.Error("expected lastPingTime to be cleaned up for stale peer")
	}
}

func TestConnectionCleaner_ActivePeerKeptAlive(t *testing.T) {
	h := testCleanupHandler()
	closer := &mockPeerCloser{}

	// Simulate a peer that pinged recently (not stale)
	h.mu.Lock()
	h.lastPingTime["active-peer"] = time.Now()
	h.mu.Unlock()

	cleaner := NewConnectionCleaner(h, closer, slog.Default()).
		WithInterval(50 * time.Millisecond).
		WithTimeout(60 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleaner.Run(ctx)

	// Wait for several sweeps
	time.Sleep(200 * time.Millisecond)
	cancel()

	closed := closer.getClosedPeers()
	if len(closed) != 0 {
		t.Errorf("expected no peers closed, got %v", closed)
	}

	// Verify ping time still exists
	h.mu.Lock()
	_, exists := h.lastPingTime["active-peer"]
	h.mu.Unlock()
	if !exists {
		t.Error("expected lastPingTime to remain for active peer")
	}
}

func TestConnectionCleaner_RunsPeriodically(t *testing.T) {
	h := testCleanupHandler()
	closer := &mockPeerCloser{}

	// Start with no stale peers
	cleaner := NewConnectionCleaner(h, closer, slog.Default()).
		WithInterval(50 * time.Millisecond).
		WithTimeout(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleaner.Run(ctx)

	// Add a peer that will become stale
	h.mu.Lock()
	h.lastPingTime["will-be-stale"] = time.Now()
	h.mu.Unlock()

	// First sweep should not close it (still fresh)
	time.Sleep(75 * time.Millisecond)
	if len(closer.getClosedPeers()) != 0 {
		t.Fatal("peer should not be closed yet")
	}

	// Wait for the timeout to expire and next sweep to fire
	time.Sleep(150 * time.Millisecond)
	cancel()

	closed := closer.getClosedPeers()
	found := false
	for _, p := range closed {
		if p == "will-be-stale" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected will-be-stale peer to be closed after timeout")
	}
}

func TestConnectionCleaner_MixedPeers(t *testing.T) {
	h := testCleanupHandler()
	closer := &mockPeerCloser{}

	now := time.Now()
	h.mu.Lock()
	h.lastPingTime["stale-1"] = now.Add(-120 * time.Second)
	h.lastPingTime["stale-2"] = now.Add(-90 * time.Second)
	h.lastPingTime["active-1"] = now.Add(-10 * time.Second)
	h.lastPingTime["active-2"] = now
	h.mu.Unlock()

	cleaner := NewConnectionCleaner(h, closer, slog.Default()).
		WithInterval(50 * time.Millisecond).
		WithTimeout(60 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleaner.Run(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()

	closed := closer.getClosedPeers()

	// Both stale peers should be closed
	staleSet := make(map[string]bool)
	for _, p := range closed {
		staleSet[p] = true
	}
	if !staleSet["stale-1"] {
		t.Error("expected stale-1 to be closed")
	}
	if !staleSet["stale-2"] {
		t.Error("expected stale-2 to be closed")
	}
	if staleSet["active-1"] {
		t.Error("active-1 should not be closed")
	}
	if staleSet["active-2"] {
		t.Error("active-2 should not be closed")
	}
}

func TestGetStalePeers_EmptyMap(t *testing.T) {
	h := testCleanupHandler()
	stale := h.GetStalePeers(60 * time.Second)
	if len(stale) != 0 {
		t.Errorf("expected 0 stale peers, got %d", len(stale))
	}
}
