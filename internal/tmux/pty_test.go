package tmux

import (
	"os"
	"strings"
	"testing"
	"time"
)

// readUntil reads from the bridge until the target string appears or timeout.
func readUntil(t *testing.T, bridge *PaneBridge, target string, timeout time.Duration) string {
	t.Helper()

	buf := make([]byte, 4096)
	var all []byte
	done := make(chan string, 1)

	go func() {
		for {
			n, err := bridge.Read(buf)
			if err != nil {
				return
			}
			all = append(all, buf[:n]...)
			if strings.Contains(string(all), target) {
				done <- string(all)
				return
			}
		}
	}()

	select {
	case output := <-done:
		return output
	case <-time.After(timeout):
		t.Fatalf("timeout waiting for %q in output (got so far: %q)", target, string(all))
		return ""
	}
}

func TestAttachPane_ReadWrite(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("bridge-rw", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	bridge, err := c.AttachPane(paneID, 80, 24)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}
	defer bridge.Close()

	// Write echo command
	if err := bridge.Write([]byte("echo BRIDGE_HELLO_42\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Read output with timeout — verify the echo output appears
	output := readUntil(t, bridge, "BRIDGE_HELLO_42", 5*time.Second)
	if !strings.Contains(output, "BRIDGE_HELLO_42") {
		t.Errorf("output missing expected string:\n%s", output)
	}
}

func TestAttachPane_EscapeSequences(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("bridge-ansi", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	bridge, err := c.AttachPane(paneID, 80, 24)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}
	defer bridge.Close()

	// Send a command that produces ANSI color escape sequences.
	// pipe-pane captures raw PTY output: the echo is literal characters
	// (\, 0, 3, 3) but printf's output contains actual ESC (0x1b) bytes.
	if err := bridge.Write([]byte("printf '\\033[31mRED\\033[0m\\n'\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Wait for the actual ESC byte to appear (only in printf output, not echo)
	output := readUntil(t, bridge, "\x1b[31m", 5*time.Second)
	if !strings.Contains(output, "\x1b[") {
		t.Errorf("expected ANSI escape sequences in output:\n%q", output)
	}
}

func TestAttachPane_Resize(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("bridge-resize", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	bridge, err := c.AttachPane(paneID, 80, 24)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}
	defer bridge.Close()

	// Resize to mobile-sized viewport
	if err := bridge.Resize(60, 20); err != nil {
		t.Fatalf("Resize: %v", err)
	}

	// Verify dimensions via ListAll
	sessions, err = c.ListAll()
	if err != nil {
		t.Fatalf("ListAll after resize: %v", err)
	}
	pane := sessions[0].Windows[0].Panes[0]
	if pane.Size.Cols != 60 {
		t.Errorf("cols = %d, want 60", pane.Size.Cols)
	}
	if pane.Size.Rows != 20 {
		t.Errorf("rows = %d, want 20", pane.Size.Rows)
	}
}

func TestAttachPane_CloseCleanup(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("bridge-close", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	bridge, err := c.AttachPane(paneID, 80, 24)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}

	fifoDir := bridge.fifoDir

	// Close the bridge
	if err := bridge.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify bridge reports closed
	if err := bridge.Write([]byte("test")); err == nil {
		t.Error("Write after Close should return error")
	}
	if _, err := bridge.Read(make([]byte, 1)); err == nil {
		t.Error("Read after Close should return error")
	}

	// Verify pane still works after bridge close
	if err := c.SendKeys(paneID, []byte("echo STILL_ALIVE\n")); err != nil {
		t.Errorf("pane should still work after bridge close: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	content, err := c.CapturePane(paneID)
	if err != nil {
		t.Fatalf("CapturePane: %v", err)
	}
	if !strings.Contains(content, "STILL_ALIVE") {
		t.Error("pane should still function after bridge close")
	}

	// Verify FIFO directory was cleaned up
	if _, err := os.Stat(fifoDir); !os.IsNotExist(err) {
		t.Error("temp directory should be removed after Close")
	}
}

func TestAttachPane_InitialContent(t *testing.T) {
	c := testClient(t)

	_, err := c.CreateSession("bridge-init", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Send something to the pane before attaching
	if err := c.SendKeys(paneID, []byte("echo PRE_ATTACH_CONTENT\n")); err != nil {
		t.Fatalf("SendKeys: %v", err)
	}
	time.Sleep(300 * time.Millisecond)

	bridge, err := c.AttachPane(paneID, 80, 24)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}
	defer bridge.Close()

	initial := bridge.InitialContent()
	if !strings.Contains(initial, "PRE_ATTACH_CONTENT") {
		t.Errorf("initial content should contain pre-attach data:\n%s", initial)
	}
}

func TestAttachPane_HostUndisturbed(t *testing.T) {
	c := testClient(t)

	// Create two sessions — attach bridge to one, verify the other is unaffected
	_, err := c.CreateSession("bridge-target", "")
	if err != nil {
		t.Fatalf("CreateSession(target): %v", err)
	}
	_, err = c.CreateSession("bridge-bystander", "")
	if err != nil {
		t.Fatalf("CreateSession(bystander): %v", err)
	}

	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}

	// Find target session pane
	var targetPaneID string
	for _, s := range sessions {
		if s.Name == "bridge-target" {
			targetPaneID = s.Windows[0].Panes[0].ID
		}
	}
	if targetPaneID == "" {
		t.Fatal("could not find target session pane")
	}

	// Attach and detach
	bridge, err := c.AttachPane(targetPaneID, 60, 20)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}
	bridge.Close()

	// Verify both sessions still exist
	sessions, err = c.ListAll()
	if err != nil {
		t.Fatalf("ListAll after detach: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	names := map[string]bool{}
	for _, s := range sessions {
		names[s.Name] = true
	}
	if !names["bridge-target"] {
		t.Error("target session should still exist")
	}
	if !names["bridge-bystander"] {
		t.Error("bystander session should still exist")
	}
}
