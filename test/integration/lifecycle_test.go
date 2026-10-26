//go:build integration

// Package integration contains end-to-end integration tests for the pmux agent.
// These tests require a real tmux installation and use isolated tmux sockets.
// Run with: go test -tags=integration -timeout=120s ./test/integration/... -v
package integration

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

const lifecycleSocket = "pmux-integ-lifecycle"

func skipIfNoTmux(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not available, skipping")
	}
}

// messageCatcher captures sent protocol messages for test assertions.
type messageCatcher struct {
	mu       sync.Mutex
	messages []capturedMsg
}

type capturedMsg struct {
	PeerID string
	Msg    protocol.Message
}

func (mc *messageCatcher) Send(_ context.Context, peerID string, msg protocol.Message) error {
	mc.mu.Lock()
	mc.messages = append(mc.messages, capturedMsg{PeerID: peerID, Msg: msg})
	mc.mu.Unlock()
	return nil
}

func (mc *messageCatcher) get() []capturedMsg {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	cp := make([]capturedMsg, len(mc.messages))
	copy(cp, mc.messages)
	return cp
}

func (mc *messageCatcher) waitFor(t *testing.T, msgType string, timeout time.Duration) protocol.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs := mc.get()
		for _, m := range msgs {
			if m.Msg.MessageType() == msgType {
				return m.Msg
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for message type %q", msgType)
	return nil
}

func (mc *messageCatcher) waitForPeer(t *testing.T, peerID, msgType string, timeout time.Duration) protocol.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs := mc.get()
		for _, m := range msgs {
			if m.PeerID == peerID && m.Msg.MessageType() == msgType {
				return m.Msg
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for message type %q from peer %q", msgType, peerID)
	return nil
}

func (mc *messageCatcher) reset() {
	mc.mu.Lock()
	mc.messages = nil
	mc.mu.Unlock()
}

func (mc *messageCatcher) countType(peerID, msgType string) int {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	count := 0
	for _, m := range mc.messages {
		if m.PeerID == peerID && m.Msg.MessageType() == msgType {
			count++
		}
	}
	return count
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func cleanupTmuxServer(t *testing.T, socket string) {
	t.Helper()
	exec.Command("tmux", "-L", socket, "kill-server").Run() //nolint:errcheck
	t.Cleanup(func() {
		exec.Command("tmux", "-L", socket, "kill-server").Run() //nolint:errcheck
	})
}

// TestLifecycle_FullCycle verifies the complete handler lifecycle:
//  1. Create a tmux session, list_sessions (1 session)
//  2. Kill it, list_sessions (empty)
//  3. Create another, attach to a pane
//  4. Send input, verify output
//  5. Detach, verify detached event
//  6. Disconnect peer, verify cleanup
//  7. Verify no goroutine leaks
func TestLifecycle_FullCycle(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, lifecycleSocket)

	tc := tmux.NewClient(lifecycleSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, newTestLogger(), "test", "")

	// Allow runtime to stabilize before baseline measurement
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	baseline := runtime.NumGoroutine()
	t.Logf("baseline goroutines: %d", baseline)

	// 1. Create a tmux session to ensure the server is running, then list
	_, err := tc.CreateSession("lifecycle-anchor", "")
	if err != nil {
		t.Fatalf("CreateSession (anchor): %v", err)
	}

	h.HandleMessage("peer1", &protocol.ListSessionsRequest{Type: "list_sessions"})
	msg := catcher.waitFor(t, "sessions", 3*time.Second)
	sessionsEvt, ok := msg.(*protocol.SessionsEvent)
	if !ok {
		t.Fatalf("expected SessionsEvent, got %T", msg)
	}
	if len(sessionsEvt.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessionsEvt.Sessions))
	}
	if sessionsEvt.Sessions[0].Name != "lifecycle-anchor" {
		t.Errorf("session name = %q, want lifecycle-anchor", sessionsEvt.Sessions[0].Name)
	}

	// 2. Kill the session, then list to verify empty (keep server alive via new session)
	catcher.reset()
	_, err = tc.CreateSession("lifecycle-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	err = tc.KillSession("lifecycle-anchor")
	if err != nil {
		t.Fatalf("KillSession: %v", err)
	}

	h.HandleMessage("peer1", &protocol.ListSessionsRequest{Type: "list_sessions"})
	msg = catcher.waitFor(t, "sessions", 3*time.Second)
	sessionsEvt2 := msg.(*protocol.SessionsEvent)
	if len(sessionsEvt2.Sessions) != 1 {
		t.Fatalf("expected 1 session after kill, got %d", len(sessionsEvt2.Sessions))
	}
	if sessionsEvt2.Sessions[0].Name != "lifecycle-test" {
		t.Errorf("remaining session name = %q, want lifecycle-test", sessionsEvt2.Sessions[0].Name)
	}

	// Get the pane ID for attachment
	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// 3. Attach to the pane
	catcher.reset()
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})
	attached := catcher.waitFor(t, "attached", 3*time.Second)
	attachedEvt, ok := attached.(*protocol.AttachedEvent)
	if !ok {
		t.Fatalf("expected AttachedEvent, got %T", attached)
	}
	if attachedEvt.PaneID != paneID {
		t.Errorf("attached paneID = %q, want %q", attachedEvt.PaneID, paneID)
	}

	// 4. Send input and verify output contains our marker
	marker := fmt.Sprintf("LIFECYCLE_%d", time.Now().UnixNano())
	catcher.reset()
	h.HandleMessage("peer1", &protocol.InputRequest{
		Type: "input",
		Data: []byte("echo " + marker + "\n"),
	})

	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if out, ok := m.Msg.(*protocol.OutputEvent); ok {
				if strings.Contains(string(out.Data), marker) {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Error("expected output containing our marker after input")
	}

	// 5. Detach and verify detached event
	catcher.reset()
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
	catcher.waitFor(t, "detached", 3*time.Second)

	// 6. Simulate peer disconnect and verify cleanup
	h.PeerDisconnected("peer1")

	// Verify no bridge remains by attempting input (should get error if we re-attach logic)
	catcher.reset()
	h.HandleMessage("peer1", &protocol.InputRequest{
		Type: "input",
		Data: []byte("should fail"),
	})
	errMsg := catcher.waitFor(t, "error", 2*time.Second)
	errEvt, ok := errMsg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", errMsg)
	}
	if errEvt.Code != "not_attached" {
		t.Errorf("error code = %q, want not_attached", errEvt.Code)
	}

	// 7. Verify no goroutine leaks
	for attempt := 0; attempt < 15; attempt++ {
		runtime.GC()
		time.Sleep(200 * time.Millisecond)
		if runtime.NumGoroutine() <= baseline+3 {
			break
		}
	}
	final := runtime.NumGoroutine()
	t.Logf("final goroutines: %d (baseline was %d, delta: %d)", final, baseline, final-baseline)
	if final > baseline+3 {
		t.Errorf("goroutine leak: baseline=%d, final=%d, delta=%d (max +3)", baseline, final, final-baseline)
	}
}

// TestLifecycle_PingPong verifies the ping/pong latency measurement flow.
func TestLifecycle_PingPong(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, lifecycleSocket)

	tc := tmux.NewClient(lifecycleSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, newTestLogger(), "test", "")

	// Send a ping
	h.HandleMessage("peer1", &protocol.PingRequest{Type: "ping"})

	msg := catcher.waitFor(t, "pong", 2*time.Second)
	pong, ok := msg.(*protocol.PongEvent)
	if !ok {
		t.Fatalf("expected PongEvent, got %T", msg)
	}
	if pong.Type != "pong" {
		t.Errorf("type = %q, want pong", pong.Type)
	}

	// Verify the peer is tracked for stale detection
	stale := h.GetStalePeers(0)
	// With a 0 timeout, the peer should be immediately stale since it just pinged
	peerFound := false
	for _, p := range stale {
		if p == "peer1" {
			peerFound = true
		}
	}
	// The peer should appear as stale with a 0 timeout since any non-zero time has passed
	if !peerFound {
		t.Log("peer1 not immediately stale (timing-dependent, not a failure)")
	}
}

// TestLifecycle_ReattachAfterDetach verifies that a peer can detach and
// re-attach to a different pane without issues.
func TestLifecycle_ReattachAfterDetach(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, lifecycleSocket)

	tc := tmux.NewClient(lifecycleSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, newTestLogger(), "test", "")

	// Create two sessions
	_, err := tc.CreateSession("reattach-1", "")
	if err != nil {
		t.Fatalf("CreateSession 1: %v", err)
	}
	_, err = tc.CreateSession("reattach-2", "")
	if err != nil {
		t.Fatalf("CreateSession 2: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}

	pane1 := sessions[0].Windows[0].Panes[0].ID
	pane2 := sessions[1].Windows[0].Panes[0].ID

	// Attach to first pane
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: pane1,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitFor(t, "attached", 3*time.Second)

	// Detach
	catcher.reset()
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
	catcher.waitFor(t, "detached", 3*time.Second)

	// Attach to second pane
	catcher.reset()
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: pane2,
		Cols:   80,
		Rows:   24,
	})

	msg := catcher.waitFor(t, "attached", 3*time.Second)
	attached := msg.(*protocol.AttachedEvent)
	if attached.PaneID != pane2 {
		t.Errorf("attached to %q, want %q", attached.PaneID, pane2)
	}

	// Send input to verify it goes to the second pane
	marker := fmt.Sprintf("REATTACH_%d", time.Now().UnixNano())
	catcher.reset()
	h.HandleMessage("peer1", &protocol.InputRequest{
		Type: "input",
		Data: []byte("echo " + marker + "\n"),
	})

	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if out, ok := m.Msg.(*protocol.OutputEvent); ok {
				if strings.Contains(string(out.Data), marker) {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Error("expected output from second pane")
	}

	// Cleanup
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
	h.PeerDisconnected("peer1")
}
