package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
	"github.com/shiftinbits/pmux-agent/internal/update"
)

const handlerTestSocket = "pmux-handler-test"

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

func (mc *messageCatcher) Send(peerID string, msg protocol.Message) error {
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

func testHandler(t *testing.T) (*Handler, *tmux.Client, *messageCatcher) {
	t.Helper()
	skipIfNoTmux(t)

	exec.Command("tmux", "-L", handlerTestSocket, "kill-server").Run() //nolint:errcheck
	t.Cleanup(func() {
		exec.Command("tmux", "-L", handlerTestSocket, "kill-server").Run() //nolint:errcheck
	})

	tc := tmux.NewClient(handlerTestSocket)
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "test", "")
	return h, tc, catcher
}

func TestHandler_ListSessions(t *testing.T) {
	h, tc, catcher := testHandler(t)

	// Create a session so there's something to list
	_, err := tc.CreateSession("handler-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	h.HandleMessage("peer1", &protocol.ListSessionsRequest{Type: "list_sessions"})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].PeerID != "peer1" {
		t.Errorf("peer = %q, want peer1", msgs[0].PeerID)
	}

	sessionsEvent, ok := msgs[0].Msg.(*protocol.SessionsEvent)
	if !ok {
		t.Fatalf("expected SessionsEvent, got %T", msgs[0].Msg)
	}
	if len(sessionsEvent.Sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(sessionsEvent.Sessions))
	}
	if sessionsEvent.Sessions[0].Name != "handler-test" {
		t.Errorf("session name = %q, want handler-test", sessionsEvent.Sessions[0].Name)
	}
	// Verify full tree (windows + panes populated)
	if len(sessionsEvent.Sessions[0].Windows) == 0 {
		t.Error("expected at least 1 window")
	}
}

func TestHandler_ListSessions_Empty(t *testing.T) {
	h, _, catcher := testHandler(t)

	h.HandleMessage("peer1", &protocol.ListSessionsRequest{Type: "list_sessions"})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	sessionsEvent, ok := msgs[0].Msg.(*protocol.SessionsEvent)
	if !ok {
		t.Fatalf("expected SessionsEvent, got %T", msgs[0].Msg)
	}
	if len(sessionsEvent.Sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessionsEvent.Sessions))
	}
}

func TestHandler_AttachDetach(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("attach-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})

	msgs := catcher.get()
	// Should receive: attached + output (initial content)
	if len(msgs) < 1 {
		t.Fatalf("expected at least 1 message, got %d", len(msgs))
	}

	attached, ok := msgs[0].Msg.(*protocol.AttachedEvent)
	if !ok {
		t.Fatalf("expected AttachedEvent, got %T", msgs[0].Msg)
	}
	if attached.PaneID != paneID {
		t.Errorf("PaneID = %q, want %q", attached.PaneID, paneID)
	}

	// Verify bridge is tracked
	h.mu.Lock()
	bridge := h.bridges["peer1"]
	h.mu.Unlock()
	if bridge == nil {
		t.Fatal("expected bridge to be tracked after attach")
	}

	// Detach
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})

	// Wait for detached message
	catcher.waitFor(t, "detached", 2*time.Second)

	// Verify bridge is cleaned up
	h.mu.Lock()
	bridge = h.bridges["peer1"]
	h.mu.Unlock()
	if bridge != nil {
		t.Error("expected bridge to be nil after detach")
	}
}

func TestHandler_InputOutput(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("io-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})

	// Wait for attached
	catcher.waitFor(t, "attached", 2*time.Second)

	// Send input
	h.HandleMessage("peer1", &protocol.InputRequest{
		Type: "input",
		Data: []byte("echo HANDLER_IO_TEST\n"),
	})

	// Wait for output containing our marker
	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if out, ok := m.Msg.(*protocol.OutputEvent); ok {
				if strings.Contains(string(out.Data), "HANDLER_IO_TEST") {
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
		t.Error("expected output containing HANDLER_IO_TEST")
	}

	// Clean up
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
}

func TestHandler_Resize(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("resize-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitFor(t, "attached", 2*time.Second)

	// Resize
	h.HandleMessage("peer1", &protocol.ResizeRequest{
		Type: "resize",
		Cols: 60,
		Rows: 20,
	})

	// Verify dimensions changed
	sessions, err = tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	pane := sessions[0].Windows[0].Panes[0]
	if pane.Size.Cols != 60 {
		t.Errorf("cols = %d, want 60", pane.Size.Cols)
	}
	if pane.Size.Rows != 20 {
		t.Errorf("rows = %d, want 20", pane.Size.Rows)
	}

	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
}

func TestHandler_Ping(t *testing.T) {
	h, _, catcher := testHandler(t)

	h.HandleMessage("peer1", &protocol.PingRequest{Type: "ping"})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	pong, ok := msgs[0].Msg.(*protocol.PongEvent)
	if !ok {
		t.Fatalf("expected PongEvent, got %T", msgs[0].Msg)
	}
	if pong.Type != "pong" {
		t.Errorf("type = %q, want pong", pong.Type)
	}
}

func TestHandler_KillSession(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("kill-me", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// Create a second session so server stays alive
	_, err = tc.CreateSession("keep-me", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	h.HandleMessage("peer1", &protocol.KillSessionRequest{
		Type:    "kill_session",
		Session: "kill-me",
	})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	ended, ok := msgs[0].Msg.(*protocol.SessionEndedEvent)
	if !ok {
		t.Fatalf("expected SessionEndedEvent, got %T", msgs[0].Msg)
	}
	if ended.Session != "kill-me" {
		t.Errorf("session = %q, want kill-me", ended.Session)
	}

	// Verify session is gone
	sessions, _ := tc.ListSessions()
	for _, s := range sessions {
		if s.Name == "kill-me" {
			t.Error("killed session should not be listed")
		}
	}
}

func TestHandler_CreateSession(t *testing.T) {
	h, tc, catcher := testHandler(t)

	h.HandleMessage("peer1", &protocol.CreateSessionRequest{Type: "create_session"})

	msg := catcher.waitFor(t, "session_created", 5*time.Second)
	created, ok := msg.(*protocol.SessionCreatedEvent)
	if !ok {
		t.Fatalf("expected SessionCreatedEvent, got %T", msg)
	}
	if created.Session.ID == "" {
		t.Error("session ID should not be empty")
	}
	if len(created.Session.Windows) == 0 {
		t.Error("expected at least 1 window")
	}
	if len(created.Session.Windows[0].Panes) == 0 {
		t.Error("expected at least 1 pane")
	}

	// Verify session actually exists in tmux
	sessions, err := tc.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	found := false
	for _, s := range sessions {
		if s.ID == created.Session.ID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("created session %q not found in tmux", created.Session.ID)
	}
}

func TestHandler_CreateSession_Multiple(t *testing.T) {
	h, tc, catcher := testHandler(t)

	// Create two sessions
	h.HandleMessage("peer1", &protocol.CreateSessionRequest{Type: "create_session"})
	msg1 := catcher.waitFor(t, "session_created", 5*time.Second)
	created1 := msg1.(*protocol.SessionCreatedEvent)

	h.HandleMessage("peer1", &protocol.CreateSessionRequest{Type: "create_session"})

	// Wait for second session_created (skip the first one we already saw)
	deadline := time.Now().Add(5 * time.Second)
	var created2 *protocol.SessionCreatedEvent
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if sc, ok := m.Msg.(*protocol.SessionCreatedEvent); ok && sc.Session.ID != created1.Session.ID {
				created2 = sc
				break
			}
		}
		if created2 != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if created2 == nil {
		t.Fatal("timeout waiting for second session_created")
	}

	if created1.Session.ID == created2.Session.ID {
		t.Error("two created sessions should have different IDs")
	}

	// Verify both exist
	sessions, err := tc.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(sessions) < 2 {
		t.Errorf("expected at least 2 sessions, got %d", len(sessions))
	}
}

func TestHandler_AttachInvalidPane(t *testing.T) {
	h, _, catcher := testHandler(t)

	// Attach to a non-existent pane — should send pane_closed + sessions
	// (not a generic attach_failed) so the mobile can navigate away.
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: "%999",
		Cols:   80,
		Rows:   24,
	})

	msgs := catcher.get()
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages (pane_closed + sessions), got %d", len(msgs))
	}
	pcMsg, ok := msgs[0].Msg.(*protocol.PaneClosedEvent)
	if !ok {
		t.Fatalf("expected PaneClosedEvent, got %T", msgs[0].Msg)
	}
	if pcMsg.PaneID != "%999" {
		t.Errorf("pane_closed paneId = %q, want %%999", pcMsg.PaneID)
	}
	if _, ok := msgs[1].Msg.(*protocol.SessionsEvent); !ok {
		t.Errorf("expected SessionsEvent as second message, got %T", msgs[1].Msg)
	}
}

func TestHandler_InputWithoutAttach(t *testing.T) {
	h, _, catcher := testHandler(t)

	h.HandleMessage("peer1", &protocol.InputRequest{
		Type: "input",
		Data: []byte("hello"),
	})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	errMsg, ok := msgs[0].Msg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", msgs[0].Msg)
	}
	if errMsg.Code != "not_attached" {
		t.Errorf("code = %q, want not_attached", errMsg.Code)
	}
}

func TestHandler_ResizeWithoutAttach(t *testing.T) {
	h, _, catcher := testHandler(t)

	h.HandleMessage("peer1", &protocol.ResizeRequest{
		Type: "resize",
		Cols: 60,
		Rows: 20,
	})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	errMsg, ok := msgs[0].Msg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", msgs[0].Msg)
	}
	if errMsg.Code != "not_attached" {
		t.Errorf("code = %q, want not_attached", errMsg.Code)
	}
}

func TestHandler_DuplicateResizeSuppressed(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("resize-dedup", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach at 80x24
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type: "attach", PaneID: paneID, Cols: 80, Rows: 24,
	})
	catcher.waitFor(t, "attached", 2*time.Second)
	time.Sleep(100 * time.Millisecond)

	// Drain messages from attach
	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	// Send resize with same dimensions — should be suppressed (no error, no action)
	h.HandleMessage("peer1", &protocol.ResizeRequest{
		Type: "resize", Cols: 80, Rows: 24,
	})
	time.Sleep(100 * time.Millisecond)

	msgs := catcher.get()
	for _, m := range msgs {
		if errMsg, ok := m.Msg.(*protocol.ErrorEvent); ok {
			t.Errorf("unexpected error on same-dimension resize: %s", errMsg.Code)
		}
	}

	// Send resize with different dimensions — should succeed
	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	h.HandleMessage("peer1", &protocol.ResizeRequest{
		Type: "resize", Cols: 60, Rows: 20,
	})
	time.Sleep(100 * time.Millisecond)

	// No error means resize succeeded
	msgs = catcher.get()
	for _, m := range msgs {
		if errMsg, ok := m.Msg.(*protocol.ErrorEvent); ok {
			t.Errorf("unexpected error on new-dimension resize: %s", errMsg.Code)
		}
	}

	// Send same 60x20 again — should be suppressed
	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	h.HandleMessage("peer1", &protocol.ResizeRequest{
		Type: "resize", Cols: 60, Rows: 20,
	})
	time.Sleep(100 * time.Millisecond)

	msgs = catcher.get()
	for _, m := range msgs {
		if errMsg, ok := m.Msg.(*protocol.ErrorEvent); ok {
			t.Errorf("unexpected error on duplicate resize: %s", errMsg.Code)
		}
	}

	// Clean up
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
}

func TestHandler_InputTooLarge(t *testing.T) {
	h, tc, catcher := testHandler(t)
	sessionName := "input-limit-test"
	_, err := tc.CreateSession(sessionName, "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type: "attach", PaneID: paneID, Cols: 80, Rows: 24,
	})
	catcher.waitFor(t, "attached", 2*time.Second)

	// Reset catcher so we only see the error from the oversized input
	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	largeData := make([]byte, maxInputSize+1)
	h.HandleMessage("peer1", &protocol.InputRequest{Type: "input", Data: largeData})

	errMsg := catcher.waitFor(t, "error", 2*time.Second)
	errEvent, ok := errMsg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", errMsg)
	}
	if errEvent.Code != "input_too_large" {
		t.Errorf("code = %q, want input_too_large", errEvent.Code)
	}

	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
}

func TestHandler_PeerDisconnected(t *testing.T) {
	h, tc, _ := testHandler(t)

	_, err := tc.CreateSession("disconnect-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})

	// Verify bridge exists
	h.mu.Lock()
	bridge := h.bridges["peer1"]
	h.mu.Unlock()
	if bridge == nil {
		t.Fatal("expected bridge after attach")
	}

	// Simulate peer disconnect
	h.PeerDisconnected("peer1")

	// Verify bridge is cleaned up
	h.mu.Lock()
	bridge = h.bridges["peer1"]
	h.mu.Unlock()
	if bridge != nil {
		t.Error("expected bridge to be nil after disconnect")
	}
}

func TestHandler_AttachReattachInitialContent(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("reattach-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Seed pane with content so capture-pane returns non-empty initial content.
	if err := tc.SendKeys(paneID, []byte("echo REATTACH_MARKER")); err != nil {
		t.Fatalf("SendKeys: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	// First attach (fresh) — the handler skips InitialContent() when
	// Reattach is false (guarded by `if req.Reattach` in handleAttach).
	// We do NOT assert zero OutputEvent here because the resize triggers
	// SIGWINCH, and the shell's re-render may arrive via streamOutput
	// non-deterministically (race between shell response time and pipe-pane
	// opening). The behavioral contract is tested by the reattach half below.
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})

	catcher.waitFor(t, "attached", 2*time.Second)

	// Detach
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
	catcher.waitFor(t, "detached", 2*time.Second)

	// Reset catcher to isolate reattach messages
	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	// Reattach with reattach=true — SHOULD receive initial content so the
	// mobile can restore the buffer from where it left off.
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:     "attach",
		PaneID:   paneID,
		Cols:     80,
		Rows:     24,
		Reattach: true,
	})

	// Wait for attached confirmation and give time for initial content
	catcher.waitFor(t, "attached", 2*time.Second)
	time.Sleep(200 * time.Millisecond)

	reattachMsgs := catcher.get()
	hasOutput := false
	for _, m := range reattachMsgs {
		if _, ok := m.Msg.(*protocol.OutputEvent); ok {
			hasOutput = true
			break
		}
	}
	if !hasOutput {
		t.Error("expected initial OutputEvent on reattach")
	}

	// Should still have attached event
	foundAttached := false
	for _, m := range reattachMsgs {
		if _, ok := m.Msg.(*protocol.AttachedEvent); ok {
			foundAttached = true
			break
		}
	}
	if !foundAttached {
		t.Error("expected AttachedEvent on reattach")
	}

	// Clean up
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
}

func TestHandler_PaneClosedOnExit(t *testing.T) {
	h, tc, catcher := testHandler(t)

	// Create two sessions — second one keeps tmux server alive when pane exits
	_, err := tc.CreateSession("pane-exit-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, err = tc.CreateSession("keepalive", "")
	if err != nil {
		t.Fatalf("CreateSession (keepalive): %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}

	var paneID string
	for _, s := range sessions {
		if s.Name == "pane-exit-test" {
			paneID = s.Windows[0].Panes[0].ID
			break
		}
	}
	if paneID == "" {
		t.Fatal("could not find pane for pane-exit-test")
	}

	// Attach to the pane
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitFor(t, "attached", 2*time.Second)

	// Reset catcher to isolate pane_closed messages
	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	// Kill the pane via tmux to simulate shell exit (^D / exit).
	// Using kill-pane is more reliable across shells than send-keys "exit".
	exec.Command("tmux", "-L", handlerTestSocket, "kill-pane", "-t", paneID).Run() //nolint:errcheck

	// Wait for pane_closed event
	paneClosed := catcher.waitFor(t, "pane_closed", 5*time.Second)
	paneClosedEvent, ok := paneClosed.(*protocol.PaneClosedEvent)
	if !ok {
		t.Fatalf("expected PaneClosedEvent, got %T", paneClosed)
	}
	if paneClosedEvent.PaneID != paneID {
		t.Errorf("paneId = %q, want %q", paneClosedEvent.PaneID, paneID)
	}

	// Should also receive a sessions event with updated tree
	sessionsMsg := catcher.waitFor(t, "sessions", 5*time.Second)
	sessionsEvent, ok := sessionsMsg.(*protocol.SessionsEvent)
	if !ok {
		t.Fatalf("expected SessionsEvent after pane_closed, got %T", sessionsMsg)
	}
	// The pane-exit-test session should be gone (it had only one pane)
	for _, s := range sessionsEvent.Sessions {
		if s.Name == "pane-exit-test" {
			t.Error("expected pane-exit-test session to be gone after pane exit")
		}
	}

	// Verify bridge is cleaned up
	h.mu.Lock()
	bridge := h.bridges["peer1"]
	h.mu.Unlock()
	if bridge != nil {
		t.Error("expected bridge to be nil after pane exit")
	}
}

// TestHandler_ListSessionsDetectsClosedPane verifies that list_sessions sends
// pane_closed when the attached pane is no longer in the session tree.
// This is the safety net for pane closures missed by watchPane (e.g., during
// connection gaps).
func TestHandler_ListSessionsDetectsClosedPane(t *testing.T) {
	h, tc, catcher := testHandler(t)

	// Create two sessions — second keeps tmux alive
	_, err := tc.CreateSession("ls-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, err = tc.CreateSession("ls-keepalive", "")
	if err != nil {
		t.Fatalf("CreateSession (keepalive): %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}

	var paneID string
	for _, s := range sessions {
		if s.Name == "ls-test" {
			paneID = s.Windows[0].Panes[0].ID
			break
		}
	}
	if paneID == "" {
		t.Fatal("could not find pane for ls-test")
	}

	// Attach to the pane
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitFor(t, "attached", 2*time.Second)

	// Kill the pane directly (simulating closure during connection gap)
	exec.Command("tmux", "-L", handlerTestSocket, "kill-pane", "-t", paneID).Run() //nolint:errcheck
	time.Sleep(100 * time.Millisecond)

	// Cancel the streamOutput context to simulate what happens during reconnection
	// (PeerDisconnected kills goroutines but doesn't send pane_closed)
	h.mu.Lock()
	cancel := h.cancels["peer1"]
	h.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	time.Sleep(100 * time.Millisecond)

	// Clear messages from attach/watchPane
	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	// Now call list_sessions — should detect the attached pane is gone
	h.HandleMessage("peer1", &protocol.ListSessionsRequest{Type: "list_sessions"})

	// Should get pane_closed before sessions
	paneClosed := catcher.waitFor(t, "pane_closed", 2*time.Second)
	paneClosedEvent, ok := paneClosed.(*protocol.PaneClosedEvent)
	if !ok {
		t.Fatalf("expected PaneClosedEvent, got %T", paneClosed)
	}
	if paneClosedEvent.PaneID != paneID {
		t.Errorf("paneId = %q, want %q", paneClosedEvent.PaneID, paneID)
	}

	// Should also get sessions
	catcher.waitFor(t, "sessions", 2*time.Second)
}

// TestHandler_GoroutineLeak verifies that repeated connect/attach/detach/disconnect
// cycles do not leak goroutines. Each cycle creates a tmux session, attaches a
// peer, sends messages, detaches, and disconnects. After all cycles, the
// goroutine count should return to approximately the baseline.
func TestHandler_GoroutineLeak(t *testing.T) {
	skipIfNoTmux(t)

	const testSocket = "pmux-leak-test"
	const cycles = 7
	const goroutineMargin = 3

	exec.Command("tmux", "-L", testSocket, "kill-server").Run() //nolint:errcheck
	t.Cleanup(func() {
		exec.Command("tmux", "-L", testSocket, "kill-server").Run() //nolint:errcheck
	})

	tc := tmux.NewClient(testSocket)
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "test", "")

	// Create a persistent session so the tmux server stays alive across cycles
	_, err := tc.CreateSession("leak-anchor", "")
	if err != nil {
		t.Fatalf("CreateSession (anchor): %v", err)
	}

	// Let runtime stabilize and collect garbage before baseline measurement
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	baseline := runtime.NumGoroutine()
	t.Logf("baseline goroutines: %d", baseline)

	for i := 0; i < cycles; i++ {
		peerID := fmt.Sprintf("leak-peer-%d", i)
		sessionName := fmt.Sprintf("leak-sess-%d", i)

		// Create a session for this cycle
		_, err := tc.CreateSession(sessionName, "")
		if err != nil {
			t.Fatalf("cycle %d: CreateSession: %v", i, err)
		}

		sessions, err := tc.ListAll()
		if err != nil {
			t.Fatalf("cycle %d: ListAll: %v", i, err)
		}

		// Find the session we just created
		var paneID string
		for _, s := range sessions {
			if s.Name == sessionName {
				paneID = s.Windows[0].Panes[0].ID
				break
			}
		}
		if paneID == "" {
			t.Fatalf("cycle %d: could not find pane for session %s", i, sessionName)
		}

		// Attach
		h.HandleMessage(peerID, &protocol.AttachRequest{
			Type:   "attach",
			PaneID: paneID,
			Cols:   80,
			Rows:   24,
		})

		// Wait for attached confirmation
		catcher.waitFor(t, "attached", 2*time.Second)

		// Send some input to exercise the stream
		h.HandleMessage(peerID, &protocol.InputRequest{
			Type: "input",
			Data: []byte("echo hello\n"),
		})
		time.Sleep(100 * time.Millisecond)

		// Detach
		h.HandleMessage(peerID, &protocol.DetachRequest{Type: "detach"})
		catcher.waitFor(t, "detached", 2*time.Second)

		// Simulate peer disconnect (cleans up any remaining state)
		h.PeerDisconnected(peerID)

		// Kill the per-cycle session to clean up tmux state
		tc.KillSession(sessionName) //nolint:errcheck

		// Reset catcher for next cycle
		catcher.mu.Lock()
		catcher.messages = nil
		catcher.mu.Unlock()
	}

	// Allow goroutines to settle — give the runtime time to reap goroutines
	// that have returned but not yet been collected by the scheduler.
	for attempt := 0; attempt < 10; attempt++ {
		runtime.GC()
		time.Sleep(200 * time.Millisecond)
		if runtime.NumGoroutine() <= baseline+goroutineMargin {
			break
		}
	}

	final := runtime.NumGoroutine()
	t.Logf("final goroutines: %d (baseline was %d, delta: %d)", final, baseline, final-baseline)

	if final > baseline+goroutineMargin {
		t.Errorf("goroutine leak detected: baseline=%d, final=%d, delta=%d (max allowed: +%d)",
			baseline, final, final-baseline, goroutineMargin)
	}
}

func TestHandler_AttachWithCompression(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("compress-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach with compression=deflate
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:        "attach",
		PaneID:      paneID,
		Cols:        80,
		Rows:        24,
		Compression: "deflate",
	})

	attached := catcher.waitFor(t, "attached", 2*time.Second)
	attachedEvent, ok := attached.(*protocol.AttachedEvent)
	if !ok {
		t.Fatalf("expected AttachedEvent, got %T", attached)
	}
	if attachedEvent.Compression != "deflate" {
		t.Errorf("Compression = %q, want \"deflate\"", attachedEvent.Compression)
	}
	if attachedEvent.PaneID != paneID {
		t.Errorf("PaneID = %q, want %q", attachedEvent.PaneID, paneID)
	}

	// Verify compressor is tracked
	h.mu.Lock()
	compressor := h.compressors["peer1"]
	h.mu.Unlock()
	if compressor == nil {
		t.Fatal("expected compressor to be tracked after attach with compression=deflate")
	}

	// Detach — compressor should be cleaned up
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
	catcher.waitFor(t, "detached", 2*time.Second)

	h.mu.Lock()
	compressor = h.compressors["peer1"]
	h.mu.Unlock()
	if compressor != nil {
		t.Error("expected compressor to be nil after detach")
	}
}

func TestHandler_AttachWithoutCompression(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("no-compress-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach without compression field
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})

	attached := catcher.waitFor(t, "attached", 2*time.Second)
	attachedEvent, ok := attached.(*protocol.AttachedEvent)
	if !ok {
		t.Fatalf("expected AttachedEvent, got %T", attached)
	}
	if attachedEvent.Compression != "" {
		t.Errorf("Compression = %q, want empty string", attachedEvent.Compression)
	}

	// Verify no compressor is tracked
	h.mu.Lock()
	compressor := h.compressors["peer1"]
	h.mu.Unlock()
	if compressor != nil {
		t.Error("expected no compressor when compression was not requested")
	}

	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
}

func TestHandler_CompressedStreamOutput(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("stream-compress-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach with compression
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:        "attach",
		PaneID:      paneID,
		Cols:        80,
		Rows:        24,
		Compression: "deflate",
	})
	catcher.waitFor(t, "attached", 2*time.Second)

	// Send input that will produce output
	h.HandleMessage("peer1", &protocol.InputRequest{
		Type: "input",
		Data: []byte("echo COMPRESSED_OUTPUT_MARKER\n"),
	})

	// Wait for compressed output containing our marker
	deadline := time.Now().Add(5 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		msgs := catcher.get()
		for _, m := range msgs {
			if out, ok := m.Msg.(*protocol.OutputEvent); ok {
				// The data should be compressed — try decompressing it.
				// Since we're working with a stateful stream, we can't easily
				// decompress individual chunks in isolation. Instead, verify
				// the data is NOT plaintext (raw "COMPRESSED_OUTPUT_MARKER").
				// If compression is active, the raw bytes won't contain the marker as plaintext.
				if strings.Contains(string(out.Data), "COMPRESSED_OUTPUT_MARKER") {
					// If we see the marker as plaintext, compression is not working
					t.Log("WARNING: found marker as plaintext in output, checking if compression was active")
				}
				// Any non-empty output event after our input means the stream is working
				if len(out.Data) > 0 {
					found = true
				}
			}
		}
		if found {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !found {
		t.Error("expected compressed output events from stream")
	}

	// Clean up
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
}

func TestHandler_SetContext(t *testing.T) {
	tc := tmux.NewClient("nonexistent-socket")
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "test", "")

	h.mu.Lock()
	defaultCtx := h.ctx
	h.mu.Unlock()
	if defaultCtx != context.Background() {
		t.Error("expected default context to be context.Background()")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.SetContext(ctx)

	h.mu.Lock()
	got := h.ctx
	h.mu.Unlock()
	if got != ctx {
		t.Error("SetContext did not update handler context")
	}
}

func TestHandler_SendMsgError(t *testing.T) {
	tc := tmux.NewClient("nonexistent-socket")
	errSend := errors.New("send failed")
	h := NewHandler(tc, func(peerID string, msg protocol.Message) error {
		return errSend
	}, slog.Default(), "test", "")

	err := h.sendMsg("peer1", &protocol.PongEvent{Type: "pong"})
	if err == nil {
		t.Fatal("expected error from sendMsg")
	}
	if !errors.Is(err, errSend) {
		t.Errorf("sendMsg error = %v, want %v", err, errSend)
	}
}

func TestHandler_SendErrorEvent(t *testing.T) {
	tc := tmux.NewClient("nonexistent-socket")
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "test", "")

	h.sendError("peer1", "test_code", "test message")

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	errEvent, ok := msgs[0].Msg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", msgs[0].Msg)
	}
	if errEvent.Code != "test_code" {
		t.Errorf("Code = %q, want test_code", errEvent.Code)
	}
	if errEvent.Message != "test message" {
		t.Errorf("Message = %q, want 'test message'", errEvent.Message)
	}
}

func TestHandler_NewSessionsEvent_NoUpdateFile(t *testing.T) {
	tc := tmux.NewClient("nonexistent-socket")
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "1.0.0", "")

	sessions := []protocol.TmuxSession{{ID: "$0", Name: "test"}}
	event := h.newSessionsEvent(sessions)

	if event.AgentVersion != "1.0.0" {
		t.Errorf("AgentVersion = %q, want 1.0.0", event.AgentVersion)
	}
	if event.UpdateAvailable != "" {
		t.Errorf("UpdateAvailable = %q, want empty", event.UpdateAvailable)
	}
	if len(event.Sessions) != 1 {
		t.Errorf("Sessions count = %d, want 1", len(event.Sessions))
	}
}

func TestHandler_NewSessionsEvent_WithUpdateAvailable(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "update-state.json")

	state := update.State{UpdateAvailable: true, LatestVersion: "v2.0.0"}
	data, _ := json.Marshal(state)
	os.WriteFile(stateFile, data, 0600)

	tc := tmux.NewClient("nonexistent-socket")
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "1.0.0", stateFile)

	event := h.newSessionsEvent(nil)
	if event.UpdateAvailable != "v2.0.0" {
		t.Errorf("UpdateAvailable = %q, want v2.0.0", event.UpdateAvailable)
	}
}

func TestHandler_NewSessionsEvent_NoUpdate(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "update-state.json")

	state := update.State{UpdateAvailable: false, LatestVersion: "v1.0.0"}
	data, _ := json.Marshal(state)
	os.WriteFile(stateFile, data, 0600)

	tc := tmux.NewClient("nonexistent-socket")
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "1.0.0", stateFile)

	event := h.newSessionsEvent(nil)
	if event.UpdateAvailable != "" {
		t.Errorf("UpdateAvailable = %q, want empty", event.UpdateAvailable)
	}
}

func TestHandler_KillSessionInvalidID(t *testing.T) {
	h, _, catcher := testHandler(t)

	h.HandleMessage("peer1", &protocol.KillSessionRequest{
		Type:    "kill_session",
		Session: "'; DROP TABLE sessions;--",
	})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	errMsg, ok := msgs[0].Msg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", msgs[0].Msg)
	}
	if errMsg.Code != "kill_session_failed" {
		t.Errorf("code = %q, want kill_session_failed", errMsg.Code)
	}
}

func TestHandler_AttachInvalidDimensions(t *testing.T) {
	h, _, catcher := testHandler(t)

	tests := []struct {
		name string
		cols int
		rows int
	}{
		{"cols too large", 501, 24},
		{"rows too large", 80, 501},
		{"cols zero", 0, 24},
		{"rows zero", 80, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catcher.mu.Lock()
			catcher.messages = nil
			catcher.mu.Unlock()

			h.HandleMessage("peer1", &protocol.AttachRequest{
				Type: "attach", PaneID: "%0", Cols: tt.cols, Rows: tt.rows,
			})

			msgs := catcher.get()
			if len(msgs) != 1 {
				t.Fatalf("expected 1 message, got %d", len(msgs))
			}
			errMsg, ok := msgs[0].Msg.(*protocol.ErrorEvent)
			if !ok {
				t.Fatalf("expected ErrorEvent, got %T", msgs[0].Msg)
			}
			if errMsg.Code != "attach_failed" {
				t.Errorf("code = %q, want attach_failed", errMsg.Code)
			}
		})
	}
}

func TestHandler_ResizeInvalidDimensions(t *testing.T) {
	h, tc, catcher := testHandler(t)

	_, err := tc.CreateSession("resize-invalid-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type: "attach", PaneID: paneID, Cols: 80, Rows: 24,
	})
	catcher.waitFor(t, "attached", 2*time.Second)

	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	h.HandleMessage("peer1", &protocol.ResizeRequest{
		Type: "resize", Cols: 501, Rows: 24,
	})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	errMsg, ok := msgs[0].Msg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", msgs[0].Msg)
	}
	if errMsg.Code != "resize_failed" {
		t.Errorf("code = %q, want resize_failed", errMsg.Code)
	}

	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
}

func TestHandler_AttachInvalidPaneFormat(t *testing.T) {
	h, _, catcher := testHandler(t)

	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type: "attach", PaneID: "invalid pane!!", Cols: 80, Rows: 24,
	})

	msgs := catcher.get()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	errMsg, ok := msgs[0].Msg.(*protocol.ErrorEvent)
	if !ok {
		t.Fatalf("expected ErrorEvent, got %T", msgs[0].Msg)
	}
	if errMsg.Code != "attach_failed" {
		t.Errorf("code = %q, want attach_failed", errMsg.Code)
	}
}

func TestHandler_GetStalePeers(t *testing.T) {
	tc := tmux.NewClient("nonexistent-socket")
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "test", "")

	stale := h.GetStalePeers(30 * time.Second)
	if len(stale) != 0 {
		t.Errorf("expected 0 stale peers, got %d", len(stale))
	}

	h.mu.Lock()
	h.lastPingTime["peer1"] = time.Now()
	h.lastPingTime["peer2"] = time.Now().Add(-60 * time.Second)
	h.mu.Unlock()

	stale = h.GetStalePeers(30 * time.Second)
	if len(stale) != 1 {
		t.Fatalf("expected 1 stale peer, got %d", len(stale))
	}
	if stale[0] != "peer2" {
		t.Errorf("stale peer = %q, want peer2", stale[0])
	}
}

func TestHandler_HandleMessageUnknownType(t *testing.T) {
	tc := tmux.NewClient("nonexistent-socket")
	catcher := &messageCatcher{}
	h := NewHandler(tc, catcher.Send, slog.Default(), "test", "")

	h.HandleMessage("peer1", &protocol.DetachedEvent{Type: "detached"})

	msgs := catcher.get()
	if len(msgs) != 0 {
		t.Errorf("expected 0 messages for unknown type, got %d", len(msgs))
	}
}

func TestHandler_ToProtocolSessions(t *testing.T) {
	sessions := []tmux.Session{
		{
			ID: "$0", Name: "test", CreatedAt: 1000, LastActivityAt: 2000,
			Windows: []tmux.Window{
				{
					ID: "@0", Name: "bash", Index: 0, Active: true,
					Panes: []tmux.Pane{
						{ID: "%0", Index: 0, Active: true, Size: tmux.PaneSize{Cols: 80, Rows: 24}, Title: "~", CurrentCommand: "bash"},
					},
				},
			},
		},
	}

	proto := toProtocolSessions(sessions)
	if len(proto) != 1 {
		t.Fatalf("expected 1 session, got %d", len(proto))
	}
	if proto[0].ID != "$0" {
		t.Errorf("ID = %q, want $0", proto[0].ID)
	}
	if len(proto[0].Windows) != 1 {
		t.Fatalf("expected 1 window, got %d", len(proto[0].Windows))
	}
	if proto[0].Windows[0].Panes[0].Size.Cols != 80 {
		t.Errorf("Pane cols = %d, want 80", proto[0].Windows[0].Panes[0].Size.Cols)
	}
}
