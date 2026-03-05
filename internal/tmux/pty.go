package tmux

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// PaneBridge provides a bidirectional byte stream to a tmux pane.
// Output is streamed via tmux pipe-pane through a FIFO, and input
// is sent via tmux send-keys -l.
//
// Internally, a relay goroutine copies from the FIFO into an os.Pipe.
// Callers read from the pipe's read end. This design ensures that
// Close() reliably unblocks any blocked Read() call — closing the pipe's
// write end causes the read end to return io.EOF immediately. The relay
// goroutine polls the FIFO with short timeouts so it can check the done
// channel and exit promptly when Close() is called.
type PaneBridge struct {
	client         *Client
	paneID         string
	fifoDir        string
	fifoFd         int      // raw fd for non-blocking FIFO reads
	pipeR          *os.File // read end of relay pipe (used by Read)
	pipeW          *os.File // write end of relay pipe (written by relay goroutine)
	done           chan struct{} // closed on Close() to signal relay to stop
	relayDone      chan struct{} // closed when relay goroutine exits
	initialContent string
	mu             sync.Mutex
	closed         bool
}

// relayPollInterval is how often the relay goroutine checks the done
// channel when the FIFO has no data. This is short enough to avoid
// perceptible lag on shutdown but long enough to avoid busy-waiting.
const relayPollInterval = 50 * time.Millisecond

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

	// Open FIFO with O_RDWR|O_NONBLOCK for non-blocking reads in the relay.
	// O_RDWR avoids blocking on open (no need to wait for a writer).
	// O_NONBLOCK allows Read to return EAGAIN when no data is available,
	// enabling the relay goroutine to check its done channel.
	fd, err := syscall.Open(fifoPath, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		os.RemoveAll(dir) //nolint:errcheck
		return nil, fmt.Errorf("open output FIFO: %w", err)
	}

	// Create a relay pipe. The relay goroutine copies FIFO data into pipeW;
	// callers read from pipeR. Closing pipeW reliably unblocks pipeR.Read().
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		syscall.Close(fd)
		os.RemoveAll(dir) //nolint:errcheck
		return nil, fmt.Errorf("create relay pipe: %w", err)
	}

	// Capture current pane content before setting up pipe-pane.
	// This provides the initial screen state (what was already displayed).
	initialContent, _ := c.CapturePane(paneID)

	// Start pipe-pane to stream pane output to our FIFO.
	// -o means output only (not input echo).
	// Shell-escape the FIFO path to handle any special characters.
	escapedPath := strings.ReplaceAll(fifoPath, "'", "'\\''")
	if _, err := c.run("pipe-pane", "-t", paneID, "-o",
		fmt.Sprintf("exec cat > '%s'", escapedPath)); err != nil {
		pipeR.Close()
		pipeW.Close()
		syscall.Close(fd)
		os.RemoveAll(dir) //nolint:errcheck
		return nil, fmt.Errorf("start pipe-pane: %w", err)
	}

	// Resize pane if dimensions are specified.
	if cols > 0 && rows > 0 {
		_ = c.ResizePane(paneID, cols, rows)
	}

	pb := &PaneBridge{
		client:         c,
		paneID:         paneID,
		fifoDir:        dir,
		fifoFd:         fd,
		pipeR:          pipeR,
		pipeW:          pipeW,
		done:           make(chan struct{}),
		relayDone:      make(chan struct{}),
		initialContent: initialContent,
	}

	// Start the relay goroutine that copies from FIFO to pipe.
	go pb.relayFIFOToPipe()

	return pb, nil
}

// relayFIFOToPipe copies data from the FIFO to the relay pipe using
// non-blocking reads. Polls the FIFO fd at short intervals and checks
// the done channel between polls so it can exit promptly on Close().
func (pb *PaneBridge) relayFIFOToPipe() {
	defer close(pb.relayDone)

	buf := make([]byte, 4096)
	for {
		// Check if we should stop
		select {
		case <-pb.done:
			return
		default:
		}

		n, err := syscall.Read(pb.fifoFd, buf)
		if n > 0 {
			if _, writeErr := pb.pipeW.Write(buf[:n]); writeErr != nil {
				// pipeW was closed — bridge is shutting down
				return
			}
		}
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				// No data available — poll after a short sleep.
				// Use a timer with select for prompt cancellation.
				timer := time.NewTimer(relayPollInterval)
				select {
				case <-pb.done:
					timer.Stop()
					return
				case <-timer.C:
				}
				continue
			}
			// FIFO error (EBADF after close, etc.) — stop relaying
			return
		}
		if n == 0 {
			// EOF on FIFO (all writers closed and no more data)
			return
		}
	}
}

// PaneID returns the ID of the pane this bridge is attached to.
func (pb *PaneBridge) PaneID() string {
	return pb.paneID
}

// InitialContent returns the pane content captured at attach time.
// This represents the screen state before pipe-pane started streaming.
func (pb *PaneBridge) InitialContent() string {
	return pb.initialContent
}

// Read reads output bytes from the pane. Blocks until data is available.
// Returns io.EOF when the bridge is closed. Implements io.Reader.
func (pb *PaneBridge) Read(buf []byte) (int, error) {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return 0, io.EOF
	}
	pb.mu.Unlock()

	n, err := pb.pipeR.Read(buf)
	if err != nil {
		return n, err
	}
	return n, nil
}

// Write sends input to the pane via tmux send-keys.
// Implements io.Writer.
func (pb *PaneBridge) Write(data []byte) (int, error) {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return 0, fmt.Errorf("bridge closed")
	}
	pb.mu.Unlock()

	if err := pb.client.SendKeys(pb.paneID, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// Resize changes the pane dimensions. Only the target pane is resized;
// other panes in the same window adjust to fill remaining space.
func (pb *PaneBridge) Resize(cols, rows int) error {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return fmt.Errorf("bridge closed")
	}
	pb.mu.Unlock()

	return pb.client.ResizePane(pb.paneID, cols, rows)
}

// Close detaches from the pane, disabling pipe-pane and cleaning up
// the FIFO, relay pipe, and temp directory. Any blocked Read call will
// return io.EOF because the pipe write end is closed.
func (pb *PaneBridge) Close() error {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return nil
	}
	pb.closed = true
	pb.mu.Unlock()

	// Disable pipe-pane (empty command removes the pipe)
	pb.client.run("pipe-pane", "-t", pb.paneID) //nolint:errcheck

	// Signal the relay goroutine to stop.
	close(pb.done)

	// Close the relay pipe write end — unblocks pipeR.Read() (io.EOF)
	// and causes the relay's pipeW.Write() to fail.
	pb.pipeW.Close()

	// Wait for relay goroutine to exit before closing the FIFO fd.
	// The relay calls syscall.Read(fifoFd), so we must not close that
	// fd while the relay is still running.
	<-pb.relayDone

	// Close the read end of the relay pipe
	pb.pipeR.Close()

	// Close the raw FIFO fd (safe now — relay has exited)
	syscall.Close(pb.fifoFd)

	// Remove temp directory and FIFO
	os.RemoveAll(pb.fifoDir) //nolint:errcheck

	return nil
}

// windowForPane returns the "session_id:window_id" target for a pane.
func (c *Client) windowForPane(paneID string) (string, error) {
	if err := validateTarget(paneID); err != nil {
		return "", fmt.Errorf("find window for pane: %w", err)
	}

	out, err := c.run("display-message", "-t", paneID, "-p", "#{session_id}:#{window_id}")
	if err != nil {
		return "", fmt.Errorf("find window for pane: %w: %s", err, out)
	}
	return strings.TrimSpace(out), nil
}
