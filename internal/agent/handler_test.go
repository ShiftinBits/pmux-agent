package agent

import (
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
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
	h := NewHandler(tc, catcher.Send, slog.Default())
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

func TestHandler_AttachInvalidPane(t *testing.T) {
	h, _, catcher := testHandler(t)

	// Attach to a non-existent pane
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: "%999",
		Cols:   80,
		Rows:   24,
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

func TestHandler_AttachReattachSkipsInitialContent(t *testing.T) {
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

	// First attach — should receive initial content
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   80,
		Rows:   24,
	})

	// Wait for attached confirmation and give time for initial content
	catcher.waitFor(t, "attached", 2*time.Second)
	time.Sleep(200 * time.Millisecond)

	msgs := catcher.get()
	hasOutput := false
	for _, m := range msgs {
		if _, ok := m.Msg.(*protocol.OutputEvent); ok {
			hasOutput = true
			break
		}
	}
	if !hasOutput {
		t.Fatal("expected initial OutputEvent on first attach")
	}

	// Detach
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
	catcher.waitFor(t, "detached", 2*time.Second)

	// Reset catcher to isolate reattach messages
	catcher.mu.Lock()
	catcher.messages = nil
	catcher.mu.Unlock()

	// Reattach with reattach=true — should NOT receive initial content
	h.HandleMessage("peer1", &protocol.AttachRequest{
		Type:     "attach",
		PaneID:   paneID,
		Cols:     80,
		Rows:     24,
		Reattach: true,
	})

	// Wait for attached confirmation and give time for any initial content
	catcher.waitFor(t, "attached", 2*time.Second)
	time.Sleep(200 * time.Millisecond)

	reattachMsgs := catcher.get()
	for _, m := range reattachMsgs {
		if _, ok := m.Msg.(*protocol.OutputEvent); ok {
			t.Error("did not expect initial OutputEvent on reattach")
		}
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
	h := NewHandler(tc, catcher.Send, slog.Default())

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
