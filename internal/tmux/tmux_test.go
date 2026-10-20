package tmux

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

func TestSendKeysDeliversBytesLiterally(t *testing.T) {
	c := testClient(t)

	payload := []byte("a\rb\nc\x1b[31md\x1b]0;t\x07 h\u00e9llo \u2713 \U0001F600\n")
	out := filepath.Join(t.TempDir(), "received")
	script := fmt.Sprintf("stty raw -echo; head -c %d > %s; sleep 30", len(payload), out)
	if o, err := c.run("new-session", "-d", "-s", "literal-test", script); err != nil {
		t.Fatalf("new-session: %v: %s", err, o)
	}
	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() error: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Let stty put the pty in raw mode before the bytes arrive.
	time.Sleep(500 * time.Millisecond)
	if err := c.SendKeys(paneID, payload); err != nil {
		t.Fatalf("SendKeys() error: %v", err)
	}

	var got []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, _ = os.ReadFile(out)
		if len(got) >= len(payload) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("received %q, want %q", got, payload)
	}

	buffers, err := c.run("list-buffers")
	if err != nil {
		t.Fatalf("list-buffers: %v: %s", err, buffers)
	}
	if strings.TrimSpace(buffers) != "" {
		t.Errorf("expected no leftover buffers, got %q", buffers)
	}
}

func TestSendKeysNulOnlyIsNoop(t *testing.T) {
	c := &Client{Socket: "pmux-never-started", TmuxBin: "tmux"}
	if err := c.SendKeys("%0", []byte{0, 0}); err != nil {
		t.Errorf("SendKeys(NUL only) error: %v", err)
	}
}

func TestTimeoutErrorOmitsPayload(t *testing.T) {
	secret := "hunter2-secret-keystrokes"
	err := timeoutError([]string{"send-keys", "-t", "%0", "-l", secret}, 3*time.Second)
	if strings.Contains(err.Error(), secret) {
		t.Errorf("timeout error leaks payload: %q", err.Error())
	}
	if want := "tmux send-keys timed out after 3s"; err.Error() != want {
		t.Errorf("timeout error = %q, want %q", err.Error(), want)
	}
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

func TestKillSession_InvalidTarget(t *testing.T) {
	c := NewClient(testSocket)
	err := c.KillSession(";evil-cmd")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("expected ErrInvalidTarget, got: %v", err)
	}
}

func TestClearWindowSizeOverride_InvalidTarget(t *testing.T) {
	c := NewClient(testSocket)
	err := c.ClearWindowSizeOverride(";evil-cmd")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if !errors.Is(err, ErrInvalidTarget) {
		t.Errorf("expected ErrInvalidTarget, got: %v", err)
	}
}

func TestClearWindowSizeOverride_NonexistentWindow(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	// A well-formed target that passes validateTarget but does not exist:
	// set-window-option fails, exercising the error-wrap path.
	if err := tc.ClearWindowSizeOverride("$99999:@99999"); err == nil {
		t.Error("expected error clearing window-size on a nonexistent window")
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

func TestPaneExists_True(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("pane-exists-true", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	if !c.PaneExists(paneID) {
		t.Errorf("PaneExists(%q) = false, want true", paneID)
	}
}

func TestPaneExists_False(t *testing.T) {
	c := testClient(t)

	// No sessions — pane %99999 cannot exist
	if c.PaneExists("%99999") {
		t.Error("PaneExists(%99999) = true, want false for nonexistent pane")
	}
}

func TestPaneExists_InvalidTarget(t *testing.T) {
	c := testClient(t)

	// Shell metacharacters in pane ID — tmux command will fail, PaneExists returns false
	if c.PaneExists(";evil-cmd") {
		t.Error("PaneExists(;evil-cmd) = true, want false for invalid target")
	}
}

func TestCursorState(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("cursor-test", "")
	if err != nil {
		t.Fatalf("CreateSession() error: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll() error: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	state, err := c.CursorState(paneID)
	if err != nil {
		t.Fatalf("CursorState() error: %v", err)
	}

	// Fresh shell: cursor should be visible, not in alternate screen
	if !state.CursorVisible {
		t.Error("CursorVisible = false, want true for normal shell")
	}
	if state.AlternateOn {
		t.Error("AlternateOn = true, want false for normal shell")
	}
	// Cursor position should be non-negative
	if state.CursorX < 0 || state.CursorY < 0 {
		t.Errorf("negative cursor position: x=%d y=%d", state.CursorX, state.CursorY)
	}
}

func TestCursorState_InvalidTarget(t *testing.T) {
	c := NewClient(testSocket)
	_, err := c.CursorState(";evil-cmd")
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
