package tmux

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// testSocket is a dedicated tmux socket for tests, isolated from pmux and default sockets.
const testSocket = "pmux-test"

func skipIfNoTmux(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not available, skipping")
	}
}

// cleanupTestSocket kills the tmux server on the test socket.
func cleanupTestSocket(t *testing.T) {
	t.Helper()
	exec.Command("tmux", "-L", testSocket, "kill-server").Run() //nolint:errcheck
}

func testClient(t *testing.T) *Client {
	t.Helper()
	skipIfNoTmux(t)
	cleanupTestSocket(t)
	t.Cleanup(func() { cleanupTestSocket(t) })
	return NewClient(testSocket)
}

func TestNewClient(t *testing.T) {
	c := NewClient("")
	if c.Socket != DefaultSocket {
		t.Errorf("Socket = %q, want %q", c.Socket, DefaultSocket)
	}

	c2 := NewClient("custom")
	if c2.Socket != "custom" {
		t.Errorf("Socket = %q, want %q", c2.Socket, "custom")
	}
}

func TestVersion(t *testing.T) {
	skipIfNoTmux(t)
	c := NewClient(testSocket)
	v, err := c.Version()
	if err != nil {
		t.Fatalf("Version() error: %v", err)
	}
	if !strings.HasPrefix(v, "tmux") {
		t.Errorf("Version() = %q, expected to start with 'tmux'", v)
	}
}

func TestIsServerRunning(t *testing.T) {
	c := testClient(t)

	// No server running initially
	if c.IsServerRunning() {
		t.Error("expected server not running initially")
	}

	// Create a session to start the server
	_, err := c.CreateSession("running-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	if !c.IsServerRunning() {
		t.Error("expected server running after CreateSession")
	}
}

func TestListSessions_Empty(t *testing.T) {
	c := testClient(t)

	sessions, err := c.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions() error: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestCreateAndListSessions(t *testing.T) {
	c := testClient(t)

	// Create two sessions
	id1, err := c.CreateSession("test-a", "")
	if err != nil {
		t.Fatalf("CreateSession(test-a) error: %v", err)
	}
	if id1 == "" {
		t.Error("expected non-empty session ID")
	}

	_, err = c.CreateSession("test-b", "")
	if err != nil {
		t.Fatalf("CreateSession(test-b) error: %v", err)
	}

	sessions, err := c.ListSessions()
	if err != nil {
		t.Fatalf("ListSessions() error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	names := map[string]bool{}
	for _, s := range sessions {
		names[s.Name] = true
		if s.ID == "" {
			t.Error("session ID should not be empty")
		}
		if s.CreatedAt == 0 {
			t.Error("session CreatedAt timestamp should not be zero")
		}
	}
	if !names["test-a"] {
		t.Error("session test-a not found")
	}
	if !names["test-b"] {
		t.Error("session test-b not found")
	}
}

func TestListWindows(t *testing.T) {
	c := testClient(t)

	id, err := c.CreateSession("win-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	windows, err := c.ListWindows(id)
	if err != nil {
		t.Fatalf("ListWindows() error: %v", err)
	}
	if len(windows) == 0 {
		t.Fatal("expected at least 1 window")
	}
	if windows[0].ID == "" {
		t.Error("window ID should not be empty")
	}
}

func TestListPanes(t *testing.T) {
	c := testClient(t)

	id, err := c.CreateSession("pane-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	windows, err := c.ListWindows(id)
	if err != nil {
		t.Fatalf("ListWindows() error: %v", err)
	}
	if len(windows) == 0 {
		t.Fatal("expected at least 1 window")
	}

	panes, err := c.ListPanes(id + ":" + windows[0].ID)
	if err != nil {
		t.Fatalf("ListPanes() error: %v", err)
	}
	if len(panes) == 0 {
		t.Fatal("expected at least 1 pane")
	}
	if panes[0].ID == "" {
		t.Error("pane ID should not be empty")
	}
	if panes[0].Size.Cols == 0 || panes[0].Size.Rows == 0 {
		t.Errorf("pane size should not be zero: %dx%d", panes[0].Size.Cols, panes[0].Size.Rows)
	}
}

func TestListAll(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("tree-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() error: %v", err)
	}
	if len(sessions) == 0 {
		t.Fatal("expected at least 1 session")
	}
	if len(sessions[0].Windows) == 0 {
		t.Fatal("expected at least 1 window")
	}
	if len(sessions[0].Windows[0].Panes) == 0 {
		t.Fatal("expected at least 1 pane")
	}
}

func TestKillSession(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("kill-me", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	sessions, _ := c.ListSessions()
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}

	if err := c.KillSession("kill-me"); err != nil {
		t.Fatalf("KillSession() error: %v", err)
	}

	sessions, _ = c.ListSessions()
	if len(sessions) != 0 {
		t.Errorf("expected 0 sessions after kill, got %d", len(sessions))
	}
}

func TestSendKeysAndCapture(t *testing.T) {
	c := testClient(t)

	id, err := c.CreateSession("keys-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// Get the first pane ID
	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() error: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Send echo command
	if err := c.SendKeys(paneID, []byte("echo TESTOUTPUT123\n")); err != nil {
		t.Fatalf("SendKeys() error: %v", err)
	}

	// Wait for command to execute
	time.Sleep(500 * time.Millisecond)

	content, err := c.CapturePane(paneID)
	if err != nil {
		t.Fatalf("CapturePane() error: %v", err)
	}

	if !strings.Contains(content, "TESTOUTPUT123") {
		t.Errorf("captured pane content does not contain 'TESTOUTPUT123':\n%s", content)
	}

	_ = id
}

func TestResizeWindow(t *testing.T) {
	c := testClient(t)

	id, err := c.CreateSession("resize-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() error: %v", err)
	}
	windowID := sessions[0].Windows[0].ID

	// Resize window to a specific size (pane fills window for single-pane)
	if err := c.ResizeWindow(id+":"+windowID, 60, 20); err != nil {
		t.Fatalf("ResizeWindow() error: %v", err)
	}

	// Verify new dimensions via pane size
	sessions, err = c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() after resize error: %v", err)
	}
	pane := sessions[0].Windows[0].Panes[0]
	if pane.Size.Cols != 60 {
		t.Errorf("cols = %d, want 60", pane.Size.Cols)
	}
	if pane.Size.Rows != 20 {
		t.Errorf("rows = %d, want 20", pane.Size.Rows)
	}
}

func TestResizePane(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("resize-pane-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() error: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	if err := c.ResizePane(paneID, 50, 15); err != nil {
		t.Fatalf("ResizePane() error: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	sessions, err = c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() after resize error: %v", err)
	}
	pane := sessions[0].Windows[0].Panes[0]
	if pane.Size.Cols != 50 {
		t.Errorf("cols = %d, want 50", pane.Size.Cols)
	}
	if pane.Size.Rows != 15 {
		t.Errorf("rows = %d, want 15", pane.Size.Rows)
	}
}

func TestPaneDimensions(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("dims-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() error: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID
	expectedCols := sessions[0].Windows[0].Panes[0].Size.Cols
	expectedRows := sessions[0].Windows[0].Panes[0].Size.Rows

	cols, rows, err := c.PaneDimensions(paneID)
	if err != nil {
		t.Fatalf("PaneDimensions() error: %v", err)
	}
	if cols != expectedCols {
		t.Errorf("cols = %d, want %d", cols, expectedCols)
	}
	if rows != expectedRows {
		t.Errorf("rows = %d, want %d", rows, expectedRows)
	}
}

func TestClient_ResizeWindowAuto(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	_, err := tc.CreateSession("auto-resize-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	windowTarget := sessions[0].ID + ":" + sessions[0].Windows[0].ID

	// Manually resize to something small
	if err := tc.ResizeWindow(windowTarget, 40, 12); err != nil {
		t.Fatalf("ResizeWindow: %v", err)
	}

	// Auto-resize should not error
	if err := tc.ResizeWindowAuto(windowTarget); err != nil {
		t.Errorf("ResizeWindowAuto: %v", err)
	}
}

func TestListWindows_InvalidTarget(t *testing.T) {
	c := NewClient(testSocket)
	_, err := c.ListWindows(";evil-cmd")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("expected ErrInvalidTarget, got: %v", err)
	}
}

func TestListPanes_InvalidTarget(t *testing.T) {
	c := NewClient(testSocket)
	_, err := c.ListPanes("$(whoami)")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("expected ErrInvalidTarget, got: %v", err)
	}
}

func TestWindowForPane_InvalidTarget(t *testing.T) {
	c := NewClient(testSocket)
	_, err := c.WindowForPane("`rm -rf /`")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("expected ErrInvalidTarget, got: %v", err)
	}
}

func TestIsolationFromDefaultSocket(t *testing.T) {
	c := testClient(t)

	// Create a session on the test socket
	_, err := c.CreateSession("isolated", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	// Create a separate client on the default socket — verify no crossover
	defaultClient := NewClient("pmux-test-default")
	defer exec.Command("tmux", "-L", "pmux-test-default", "kill-server").Run() //nolint:errcheck

	sessions, _ := defaultClient.ListSessions()
	for _, s := range sessions {
		if s.Name == "isolated" {
			t.Error("test session should NOT be visible on a different socket")
		}
	}
}
