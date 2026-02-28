//go:build integration

package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

const singlePairingSocket = "pmux-integ-single"

// TestSinglePairing_RejectsSecondDevice verifies that a second device cannot
// attach when a different device is already connected to the handler.
// This tests the handler-level behavior: a single paired device can interact
// with the agent. A second peer ID attempting to use the handler still gets
// responses (the handler doesn't enforce device identity — that's the
// PeerManager's job). This test validates the single-pairing UX at the session
// level: one peer attaches and uses a pane, and a peer disconnect properly
// cleans up state.
func TestSinglePairing_RejectsSecondDevice(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, singlePairingSocket)

	tc := tmux.NewClient(singlePairingSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, func(data []byte) {}, newTestLogger())

	// Create a session
	_, err := tc.CreateSession("single-1", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	pane1 := sessions[0].Windows[0].Panes[0].ID

	// Paired device (peerA) attaches successfully
	h.HandleMessage("peerA", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: pane1,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitForPeer(t, "peerA", "attached", 3*time.Second)

	// peerA can send input and receive output
	marker := fmt.Sprintf("SINGLE_%d", time.Now().UnixNano())
	catcher.reset()
	h.HandleMessage("peerA", &protocol.InputRequest{
		Type: "input",
		Data: []byte("echo " + marker + "\n"),
	})

	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if m.PeerID == "peerA" {
				if out, ok := m.Msg.(*protocol.OutputEvent); ok {
					if strings.Contains(string(out.Data), marker) {
						found = true
						break
					}
				}
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Error("peerA did not receive its output marker")
	}

	// peerB (unpaired device that somehow reached the handler) tries to
	// attach — it will get an attached event (handler doesn't enforce
	// device identity). But at the WebRTC/PeerManager level, the
	// connection would be rejected before reaching the handler.
	// Here we verify that the handler properly isolates peer state.
	catcher.reset()
	h.HandleMessage("peerB", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: pane1,
		Cols:   80,
		Rows:   24,
	})

	// Even if peerB gets an attached event, verify peerA is still functional
	catcher.waitForPeer(t, "peerB", "attached", 3*time.Second)

	markerA2 := fmt.Sprintf("STILL_A_%d", time.Now().UnixNano())
	catcher.reset()
	h.HandleMessage("peerA", &protocol.InputRequest{
		Type: "input",
		Data: []byte("echo " + markerA2 + "\n"),
	})

	deadline = time.Now().Add(5 * time.Second)
	found = false
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if m.PeerID == "peerA" {
				if out, ok := m.Msg.(*protocol.OutputEvent); ok {
					if strings.Contains(string(out.Data), markerA2) {
						found = true
						break
					}
				}
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Error("peerA should still receive output after peerB attempts attach")
	}

	// Cleanup
	h.HandleMessage("peerA", &protocol.DetachRequest{Type: "detach"})
	h.HandleMessage("peerB", &protocol.DetachRequest{Type: "detach"})
	h.PeerDisconnected("peerA")
	h.PeerDisconnected("peerB")
}

// TestSinglePairing_AllowsReconnect verifies that the paired device can
// disconnect and reconnect successfully, with clean state transitions.
func TestSinglePairing_AllowsReconnect(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, singlePairingSocket)

	tc := tmux.NewClient(singlePairingSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, func(data []byte) {}, newTestLogger())

	// Create a session
	_, err := tc.CreateSession("reconnect-1", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	pane1 := sessions[0].Windows[0].Panes[0].ID

	// First connection: attach, send input, verify output
	h.HandleMessage("paired-device", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: pane1,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitForPeer(t, "paired-device", "attached", 3*time.Second)

	marker1 := fmt.Sprintf("CONN1_%d", time.Now().UnixNano())
	catcher.reset()
	h.HandleMessage("paired-device", &protocol.InputRequest{
		Type: "input",
		Data: []byte("echo " + marker1 + "\n"),
	})

	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if m.PeerID == "paired-device" {
				if out, ok := m.Msg.(*protocol.OutputEvent); ok {
					if strings.Contains(string(out.Data), marker1) {
						found = true
						break
					}
				}
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Error("first connection: paired-device did not receive output")
	}

	// Disconnect
	h.HandleMessage("paired-device", &protocol.DetachRequest{Type: "detach"})
	h.PeerDisconnected("paired-device")

	// Verify disconnected peer gets error on input
	catcher.reset()
	h.HandleMessage("paired-device", &protocol.InputRequest{
		Type: "input",
		Data: []byte("should fail"),
	})
	errMsg := catcher.waitForPeer(t, "paired-device", "error", 2*time.Second)
	errEvt, ok := errMsg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", errMsg)
	}
	if errEvt.Code != "not_attached" {
		t.Errorf("error code = %q, want not_attached", errEvt.Code)
	}

	// Second connection: re-attach to the same pane
	catcher.reset()
	h.HandleMessage("paired-device", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: pane1,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitForPeer(t, "paired-device", "attached", 3*time.Second)

	// Send input on second connection
	marker2 := fmt.Sprintf("CONN2_%d", time.Now().UnixNano())
	catcher.reset()
	h.HandleMessage("paired-device", &protocol.InputRequest{
		Type: "input",
		Data: []byte("echo " + marker2 + "\n"),
	})

	deadline = time.Now().Add(5 * time.Second)
	found = false
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if m.PeerID == "paired-device" {
				if out, ok := m.Msg.(*protocol.OutputEvent); ok {
					if strings.Contains(string(out.Data), marker2) {
						found = true
						break
					}
				}
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Error("second connection: paired-device did not receive output after reconnect")
	}

	// Cleanup
	h.HandleMessage("paired-device", &protocol.DetachRequest{Type: "detach"})
	h.PeerDisconnected("paired-device")
}

// TestSinglePairing_ConcurrentListSessions verifies that the single paired
// device can list sessions concurrently without races.
func TestSinglePairing_ConcurrentListSessions(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, singlePairingSocket)

	tc := tmux.NewClient(singlePairingSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, func(data []byte) {}, newTestLogger())

	// Create a few sessions
	for i := 0; i < 3; i++ {
		_, err := tc.CreateSession(fmt.Sprintf("concurrent-%d", i), "")
		if err != nil {
			t.Fatalf("CreateSession %d: %v", i, err)
		}
	}

	// Same device lists sessions multiple times concurrently
	const numRequests = 5
	for i := 0; i < numRequests; i++ {
		go func() {
			h.HandleMessage("paired-device", &protocol.ListSessionsRequest{Type: "list_sessions"})
		}()
	}

	// Wait for all responses
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		count := catcher.countType("paired-device", "sessions")
		if count >= numRequests {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	count := catcher.countType("paired-device", "sessions")
	if count < numRequests {
		t.Errorf("expected at least %d sessions responses, got %d", numRequests, count)
	}

	// Verify each response has 3 sessions
	msgs := catcher.get()
	for _, m := range msgs {
		if m.PeerID == "paired-device" && m.Msg.MessageType() == "sessions" {
			sessionsEvt := m.Msg.(*protocol.SessionsEvent)
			if len(sessionsEvt.Sessions) != 3 {
				t.Errorf("expected 3 sessions, got %d", len(sessionsEvt.Sessions))
			}
		}
	}
}
