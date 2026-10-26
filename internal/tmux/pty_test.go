package tmux

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestShellQuote(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple path", "/tmp/pmux-bridge-123/output", "'/tmp/pmux-bridge-123/output'"},
		{"path with spaces", "/tmp/my dir/output", "'/tmp/my dir/output'"},
		{"path with single quote", "/tmp/it's/output", "'/tmp/it'\\''s/output'"},
		{"path with dollar expansion", "/tmp/$(rm -rf)/output", "'/tmp/$(rm -rf)/output'"},
		{"path with backticks", "/tmp/`whoami`/output", "'/tmp/`whoami`/output'"},
		{"empty string", "", "''"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shellQuote(tt.input)
			if got != tt.want {
				t.Errorf("shellQuote(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

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
	if _, err := bridge.Write([]byte("echo BRIDGE_HELLO_42\n")); err != nil {
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
	if _, err := bridge.Write([]byte("printf '\\033[31mRED\\033[0m\\n'\n")); err != nil {
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
	if _, err := bridge.Write([]byte("test")); err == nil {
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

func TestPaneBridge_AttachPane_NonexistentPane(t *testing.T) {
	c := testClient(t)

	// No sessions started — pane %99999 does not exist.
	// pipe-pane will fail because the target is unknown to tmux.
	_, err := c.AttachPane("%99999", 80, 24)
	if err == nil {
		t.Fatal("AttachPane with nonexistent pane should return error")
	}
}

func TestPaneBridge_AttachPane_InvalidPaneID(t *testing.T) {
	c := testClient(t)

	// Pane ID containing shell metacharacters.
	// pipe-pane will fail because tmux rejects the invalid target.
	_, err := c.AttachPane(";evil-cmd", 80, 24)
	if err == nil {
		t.Fatal("AttachPane with invalid pane ID should return error")
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

func TestAttachPane_ReplacesExistingPipe(t *testing.T) {
	skipIfNoTmux(t)
	const socket = "pmux-pty-prepipe-test"
	c := NewClient(socket)
	cleanup := func() {
		_ = exec.Command("tmux", "-L", socket, "kill-server").Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := c.CreateSession("prepipe", ""); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	if _, err := c.run("pipe-pane", "-t", paneID, "cat >/dev/null"); err != nil {
		t.Fatalf("pre-existing pipe-pane: %v", err)
	}
	out, err := c.run("display", "-p", "-t", paneID, "#{pane_pipe}")
	if err != nil {
		t.Fatalf("display pane_pipe: %v", err)
	}
	if strings.TrimSpace(out) != "1" {
		t.Fatalf("pane_pipe = %q before attach, want 1", strings.TrimSpace(out))
	}

	bridge, err := c.AttachPane(paneID, 80, 24)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}
	defer bridge.Close()

	marker := "PREPIPE_MARKER_77"
	if _, err := bridge.Write([]byte("echo " + marker + "\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	readUntil(t, bridge, marker, 5*time.Second)
}

// newPollTestClient returns a client on a dedicated socket for the FIFO
// readiness tests, killing the server before and after the test.
func newPollTestClient(t *testing.T) *Client {
	t.Helper()
	skipIfNoTmux(t)
	const socket = "pmux-fifo-poll-test"
	kill := func() { _ = exec.Command("tmux", "-L", socket, "kill-server").Run() }
	kill()
	t.Cleanup(kill)
	return NewClient(socket)
}

func TestAttachPane_ClosePromptlyWhenIdle(t *testing.T) {
	c := newPollTestClient(t)
	if _, err := c.CreateSession("poll-close", ""); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	bridge, err := c.AttachPane(sessions[0].Windows[0].Panes[0].ID, 80, 24)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}

	// Let the relay settle into its idle poll, then close. Close returns only
	// after the relay exits, so its duration bounds the relay's shutdown: one
	// poll interval plus the pipe-pane subprocess.
	time.Sleep(100 * time.Millisecond)
	const closeBound = 200 * time.Millisecond
	start := time.Now()
	closeDone := make(chan struct{})
	go func() {
		_ = bridge.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return")
	}
	if elapsed := time.Since(start); elapsed > closeBound {
		t.Errorf("Close took %v, want under %v", elapsed, closeBound)
	}
}

func TestAttachPane_EchoLatency(t *testing.T) {
	c := newPollTestClient(t)
	if _, err := c.CreateSession("poll-latency", ""); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	bridge, err := c.AttachPane(sessions[0].Windows[0].Panes[0].ID, 80, 24)
	if err != nil {
		t.Fatalf("AttachPane: %v", err)
	}
	defer bridge.Close()

	const samples = 30
	var lat []time.Duration
	for i := 0; i < samples; i++ {
		marker := fmt.Sprintf("Q%dZ", i)
		if _, err := bridge.Write([]byte(marker)); err != nil {
			t.Fatalf("Write: %v", err)
		}
		start := time.Now()
		readUntil(t, bridge, marker, 5*time.Second)
		lat = append(lat, time.Since(start))
	}
	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
	median := lat[len(lat)/2]
	t.Logf("write-return to bridge Read latency: min=%v median=%v max=%v", lat[0], median, lat[len(lat)-1])
	// A relay that sleeps after an empty read puts the median near half the
	// interval; waking on readability keeps it to a few milliseconds.
	if bound := relayPollInterval / 4; median >= bound {
		t.Errorf("median echo latency %v, want under %v (relay poll interval %v)", median, bound, relayPollInterval)
	}
}

// TestAttachPane_SecondAttachDisplacesFirst checks that a second bridge on the
// same pane takes over the pipe: the first bridge's Read ends with
// ErrBridgeDisplaced instead of blocking forever, and closing the first bridge
// leaves the second one's pipe streaming.
func TestAttachPane_SecondAttachDisplacesFirst(t *testing.T) {
	skipIfNoTmux(t)
	const socket = "pmux-pipe-displace-test"
	kill := func() { _ = exec.Command("tmux", "-L", socket, "kill-server").Run() }
	kill()
	t.Cleanup(kill)
	c := NewClient(socket)

	if _, err := c.CreateSession("displace", ""); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sessions, err := c.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	first, err := c.AttachPane(paneID, 80, 24)
	if err != nil {
		t.Fatalf("first AttachPane: %v", err)
	}
	defer first.Close()
	firstErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := first.Read(buf); err != nil {
				firstErr <- err
				return
			}
		}
	}()

	second, err := c.AttachPane(paneID, 80, 24)
	if err != nil {
		t.Fatalf("second AttachPane: %v", err)
	}
	defer second.Close()

	select {
	case err := <-firstErr:
		if !errors.Is(err, ErrBridgeDisplaced) {
			t.Errorf("first bridge Read error = %v, want ErrBridgeDisplaced", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first bridge Read still blocked after a second attach")
	}

	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if _, err := second.Write([]byte("echo DISPLACE_SURVIVES\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	readUntil(t, second, "DISPLACE_SURVIVES", 5*time.Second)
}
