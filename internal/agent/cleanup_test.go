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
	}, slog.Default())
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

// --- PeerStateChecker safety-net tests ---

// mockStateChecker returns peer states for testing. Thread-safe so it can
// be mutated (e.g., removing entries to simulate ClosePeer) while the
// cleaner goroutine reads it.
type mockStateChecker struct {
	mu     sync.Mutex
	states map[string]string
}

func (m *mockStateChecker) PeerStates() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make(map[string]string, len(m.states))
	for k, v := range m.states {
		cp[k] = v
	}
	return cp
}

func (m *mockStateChecker) remove(deviceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.states, deviceID)
}

func TestConnectionCleaner_SweepClosesFailedPCState(t *testing.T) {
	h := testCleanupHandler()
	closer := &mockPeerCloser{}
	checker := &mockStateChecker{
		states: map[string]string{
			"failed-peer": "failed",
			"closed-peer": "closed",
		},
	}

	cleaner := NewConnectionCleaner(h, closer, slog.Default()).
		WithInterval(50 * time.Millisecond).
		WithTimeout(60 * time.Second).
		WithStateChecker(checker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleaner.Run(ctx)

	// Wait for at least one sweep
	time.Sleep(200 * time.Millisecond)
	cancel()

	closed := closer.getClosedPeers()
	closedSet := make(map[string]bool)
	for _, p := range closed {
		closedSet[p] = true
	}

	if !closedSet["failed-peer"] {
		t.Error("expected failed-peer to be closed by safety-net sweep")
	}
	if !closedSet["closed-peer"] {
		t.Error("expected closed-peer to be closed by safety-net sweep")
	}
}

func TestConnectionCleaner_SweepIgnoresConnectedPCState(t *testing.T) {
	h := testCleanupHandler()
	closer := &mockPeerCloser{}
	checker := &mockStateChecker{
		states: map[string]string{
			"connected-peer":    "connected",
			"new-peer":          "new",
			"disconnected-peer": "disconnected",
		},
	}

	cleaner := NewConnectionCleaner(h, closer, slog.Default()).
		WithInterval(50 * time.Millisecond).
		WithTimeout(60 * time.Second).
		WithStateChecker(checker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleaner.Run(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()

	closed := closer.getClosedPeers()
	if len(closed) != 0 {
		t.Errorf("expected no peers closed for connected/new/disconnected states, got %v", closed)
	}
}

func TestConnectionCleaner_SweepNoDoubleClose(t *testing.T) {
	h := testCleanupHandler()

	checker := &mockStateChecker{
		states: map[string]string{
			"stale-and-failed": "failed",
		},
	}

	// Use a closer that removes the peer from the state checker when closed,
	// simulating real PeerManager behavior where ClosePeer removes the peer.
	closer := &mockPeerCloserWithStateCleanup{
		mockPeerCloser: mockPeerCloser{},
		checker:        checker,
	}

	// Peer is both stale (idle timeout) AND has failed PC state.
	// Within a single sweep it should only be closed once (by idle check,
	// since it runs first). The state checker removal prevents subsequent
	// sweeps from double-closing.
	h.mu.Lock()
	h.lastPingTime["stale-and-failed"] = time.Now().Add(-90 * time.Second)
	h.mu.Unlock()

	cleaner := NewConnectionCleaner(h, closer, slog.Default()).
		WithInterval(50 * time.Millisecond).
		WithTimeout(60 * time.Second).
		WithStateChecker(checker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleaner.Run(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()

	closed := closer.getClosedPeers()
	// Count how many times stale-and-failed was closed
	count := 0
	for _, p := range closed {
		if p == "stale-and-failed" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected stale-and-failed to be closed exactly once, got %d times", count)
	}
}

// mockPeerCloserWithStateCleanup wraps mockPeerCloser and removes peers from
// the state checker when closed, simulating real PeerManager behavior.
type mockPeerCloserWithStateCleanup struct {
	mockPeerCloser
	checker *mockStateChecker
}

func (m *mockPeerCloserWithStateCleanup) ClosePeer(deviceID string) {
	m.mockPeerCloser.ClosePeer(deviceID)
	m.checker.remove(deviceID)
}

func TestConnectionCleaner_WithoutStateChecker(t *testing.T) {
	h := testCleanupHandler()
	closer := &mockPeerCloser{}

	// No stale peers, no state checker — should close nothing.
	cleaner := NewConnectionCleaner(h, closer, slog.Default()).
		WithInterval(50 * time.Millisecond).
		WithTimeout(60 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go cleaner.Run(ctx)

	time.Sleep(200 * time.Millisecond)
	cancel()

	closed := closer.getClosedPeers()
	if len(closed) != 0 {
		t.Errorf("expected no peers closed without state checker, got %v", closed)
	}
}
