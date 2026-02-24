package tmux

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// PaneBridge provides a bidirectional byte stream to a tmux pane.
// Output is streamed via tmux pipe-pane through a FIFO, and input
// is sent via tmux send-keys -l.
type PaneBridge struct {
	client         *Client
	paneID         string
	fifoDir        string
	fifo           *os.File
	initialContent string
	mu             sync.Mutex
	closed         bool
}

// AttachPane creates a bidirectional stream to a tmux pane.
// Output is captured via pipe-pane and input is sent via send-keys.
// If cols and rows are positive, the pane's window is resized to those dimensions.
func (c *Client) AttachPane(paneID string, cols, rows int) (*PaneBridge, error) {
	// Create temp directory for the output FIFO
	dir, err := os.MkdirTemp("", "pmux-bridge-*")
	if err != nil {
		return nil, fmt.Errorf("create bridge temp dir: %w", err)
	}

	fifoPath := filepath.Join(dir, "output")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		os.RemoveAll(dir) //nolint:errcheck
		return nil, fmt.Errorf("create output FIFO: %w", err)
	}

	// Open FIFO with O_RDWR to avoid blocking on open.
	// O_RDONLY would block until a writer opens the other end;
	// O_RDWR returns immediately and reads block until data arrives.
	fifo, err := os.OpenFile(fifoPath, os.O_RDWR, 0)
	if err != nil {
		os.RemoveAll(dir) //nolint:errcheck
		return nil, fmt.Errorf("open output FIFO: %w", err)
	}

	// Capture current pane content before setting up pipe-pane.
	// This provides the initial screen state (what was already displayed).
	initialContent, _ := c.CapturePane(paneID)

	// Start pipe-pane to stream pane output to our FIFO.
	// -o means output only (not input echo).
	if _, err := c.run("pipe-pane", "-t", paneID, "-o",
		fmt.Sprintf("exec cat > '%s'", fifoPath)); err != nil {
		fifo.Close()
		os.RemoveAll(dir) //nolint:errcheck
		return nil, fmt.Errorf("start pipe-pane: %w", err)
	}

	// Resize pane's window if dimensions are specified.
	if cols > 0 && rows > 0 {
		if wt, err := c.windowForPane(paneID); err == nil {
			_ = c.ResizeWindow(wt, cols, rows)
		}
	}

	return &PaneBridge{
		client:         c,
		paneID:         paneID,
		fifoDir:        dir,
		fifo:           fifo,
		initialContent: initialContent,
	}, nil
}

// InitialContent returns the pane content captured at attach time.
// This represents the screen state before pipe-pane started streaming.
func (pb *PaneBridge) InitialContent() string {
	return pb.initialContent
}

// Read reads output bytes from the pane. Blocks until data is available.
// Implements io.Reader.
func (pb *PaneBridge) Read(buf []byte) (int, error) {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return 0, fmt.Errorf("bridge closed")
	}
	pb.mu.Unlock()

	return pb.fifo.Read(buf)
}

// Write sends input to the pane via tmux send-keys.
func (pb *PaneBridge) Write(data []byte) error {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return fmt.Errorf("bridge closed")
	}
	pb.mu.Unlock()

	return pb.client.SendKeys(pb.paneID, data)
}

// Resize changes the pane dimensions by resizing the containing window.
func (pb *PaneBridge) Resize(cols, rows int) error {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return fmt.Errorf("bridge closed")
	}
	pb.mu.Unlock()

	windowTarget, err := pb.client.windowForPane(pb.paneID)
	if err != nil {
		return fmt.Errorf("find window for resize: %w", err)
	}
	return pb.client.ResizeWindow(windowTarget, cols, rows)
}

// Close detaches from the pane, disabling pipe-pane and cleaning up
// the FIFO and temp directory. Any blocked Read call will return an error.
func (pb *PaneBridge) Close() error {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	if pb.closed {
		return nil
	}
	pb.closed = true

	// Disable pipe-pane (empty command removes the pipe)
	pb.client.run("pipe-pane", "-t", pb.paneID) //nolint:errcheck

	// Close FIFO (unblocks any pending Read)
	pb.fifo.Close()

	// Remove temp directory and FIFO
	os.RemoveAll(pb.fifoDir) //nolint:errcheck

	return nil
}

// windowForPane returns the "session_id:window_id" target for a pane.
func (c *Client) windowForPane(paneID string) (string, error) {
	out, err := c.run("display-message", "-t", paneID, "-p", "#{session_id}:#{window_id}")
	if err != nil {
		return "", fmt.Errorf("find window for pane: %w: %s", err, out)
	}
	return strings.TrimSpace(out), nil
}
