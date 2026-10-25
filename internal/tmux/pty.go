package tmux

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// shellQuote wraps s in POSIX single quotes, escaping each embedded
// single quote by closing the quoted string, emitting an escaped quote
// (\'), and reopening it. The result is safe to embed as a single token
// in a shell command string.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// ErrBridgeDisplaced is returned by PaneBridge.Read once a newer AttachPane on
// the same pane has replaced this bridge's pipe: tmux allows one pipe per pane,
// so this bridge will receive no further output.
var ErrBridgeDisplaced = errors.New("pane bridge displaced by a newer attach")

// PaneBridge provides a bidirectional byte stream to a tmux pane.
// Output is streamed via tmux pipe-pane through a FIFO, and input
// is sent via SendKeys (load-buffer + paste-buffer, never send-keys argv).
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
	fifoFd         int           // raw fd for non-blocking FIFO reads
	pipeR          *os.File      // read end of relay pipe (used by Read)
	pipeW          *os.File      // write end of relay pipe (written by relay goroutine)
	done           chan struct{} // closed on Close() to signal relay to stop
	relayDone      chan struct{} // closed when relay goroutine exits
	initialContent string
	mu             sync.Mutex
	closed         bool
	displaced      bool // set when a newer bridge replaced this one's pipe
}

// relayPollInterval is the longest the relay goroutine waits in poll(2)
// before re-checking the done channel when the FIFO has no data. Data wakes
// the poll immediately; the interval only bounds shutdown latency.
const relayPollInterval = 50 * time.Millisecond

// AttachPane creates a bidirectional stream to a tmux pane.
// Output is captured via pipe-pane and input is sent via SendKeys.
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

	// Start pipe-pane to stream pane output to our FIFO.
	// Output-only is pipe-pane's default (no -I/-O flags). -o is deliberately
	// omitted: it means "only open a new pipe if none is open" and toggles an
	// existing pipe off, so attaching would silently fail to stream. Without
	// it, tmux replaces any existing pipe on the pane with ours. A user's own
	// pipe-pane on this pane is therefore replaced; detaching stops our pipe.
	// The FIFO path is passed as a positional argument ($0) to an inner
	// sh -c, so it is never interpreted as shell syntax — only as data.
	// This prevents command injection even if the path contained $(...)
	// or backtick sequences.
	//
	// The pipe and the ownership record change together under pipesMu, so
	// the record always names the bridge whose pipe tmux has open. A bridge
	// this replaces is told so, since its FIFO will get no more output.
	c.pipesMu.Lock()
	if _, err := c.run("pipe-pane", "-t", paneID,
		fmt.Sprintf("exec sh -c 'cat > \"$0\"' %s", shellQuote(fifoPath))); err != nil {
		c.pipesMu.Unlock()
		pipeR.Close()
		pipeW.Close()
		syscall.Close(fd)
		os.RemoveAll(dir) //nolint:errcheck
		return nil, fmt.Errorf("start pipe-pane: %w", err)
	}
	if c.pipes == nil {
		c.pipes = make(map[string]*PaneBridge)
	}
	prev := c.pipes[paneID]
	c.pipes[paneID] = pb
	c.pipesMu.Unlock()
	if prev != nil {
		prev.displace()
	}

	// Resize pane if dimensions are specified.
	if cols > 0 && rows > 0 {
		_ = c.ResizePane(paneID, cols, rows)
	}

	// Start the relay goroutine that copies from FIFO to pipe.
	go pb.relayFIFOToPipe()

	return pb, nil
}

// waitReadable blocks until the FIFO fd is readable or relayPollInterval
// elapses, retrying on EINTR. Any other poll error returns immediately so
// the caller's next read surfaces it.
func (pb *PaneBridge) waitReadable() {
	fds := []unix.PollFd{{Fd: int32(pb.fifoFd), Events: unix.POLLIN}}
	deadline := time.Now().Add(relayPollInterval)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return
		}
		ms := int(remaining / time.Millisecond)
		if ms < 1 {
			ms = 1
		}
		if _, err := unix.Poll(fds, ms); err != unix.EINTR {
			return
		}
	}
}

// relayFIFOToPipe copies data from the FIFO to the relay pipe using
// non-blocking reads. When the FIFO is empty it waits in poll(2) for
// readability (waking immediately on data) for at most relayPollInterval,
// and checks the done channel between polls so it exits within one interval
// on Close().
func (pb *PaneBridge) relayFIFOToPipe() {
	defer close(pb.relayDone)
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic in relayFIFOToPipe: %v\n", r)
		}
	}()

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
				// No data available — block in poll(2) until the FIFO is
				// readable or the interval elapses, then re-check done.
				pb.waitReadable()
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
// Returns io.EOF when the bridge is closed, and ErrBridgeDisplaced once a
// newer bridge on the same pane has taken over the pipe. Implements io.Reader.
func (pb *PaneBridge) Read(buf []byte) (int, error) {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return 0, io.EOF
	}
	pb.mu.Unlock()

	n, err := pb.pipeR.Read(buf)
	if err != nil {
		pb.mu.Lock()
		displaced := pb.displaced && !pb.closed
		pb.mu.Unlock()
		if displaced {
			return n, ErrBridgeDisplaced
		}
		return n, err
	}
	return n, nil
}

// displace marks the bridge as replaced by a newer bridge on the same pane
// and closes the relay pipe's write end, so a blocked Read returns
// ErrBridgeDisplaced instead of waiting on a FIFO tmux no longer writes to.
// The bridge still needs Close to release its FIFO and temp directory.
func (pb *PaneBridge) displace() {
	pb.mu.Lock()
	if pb.closed || pb.displaced {
		pb.mu.Unlock()
		return
	}
	pb.displaced = true
	pb.mu.Unlock()
	pb.pipeW.Close()
}

// Write sends input to the pane via SendKeys (load-buffer + paste-buffer).
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

// Close detaches from the pane, disabling pipe-pane if this bridge's pipe
// is still the pane's current one, and cleans up the FIFO, relay pipe, and
// temp directory. Any blocked Read call will return io.EOF because the pipe
// write end is closed.
func (pb *PaneBridge) Close() error {
	pb.mu.Lock()
	if pb.closed {
		pb.mu.Unlock()
		return nil
	}
	pb.closed = true
	pb.mu.Unlock()

	pb.client.releasePipe(pb)

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

// releasePipe disables pipe-pane on pb's pane (an empty command removes the
// pipe), but only while pb owns it: a pipe a newer bridge installed is left
// running.
func (c *Client) releasePipe(pb *PaneBridge) {
	c.pipesMu.Lock()
	defer c.pipesMu.Unlock()
	if c.pipes[pb.paneID] != pb {
		return
	}
	delete(c.pipes, pb.paneID)
	c.run("pipe-pane", "-t", pb.paneID) //nolint:errcheck
}

// WindowForPane returns the "session_id:window_id" target for a pane.
func (c *Client) WindowForPane(paneID string) (string, error) {
	if err := validateTarget(paneID); err != nil {
		return "", fmt.Errorf("find window for pane: %w", err)
	}

	out, err := c.run("display-message", "-t", paneID, "-p", "#{session_id}:#{window_id}")
	if err != nil {
		return "", fmt.Errorf("find window for pane: %w: %s", err, out)
	}
	return strings.TrimSpace(out), nil
}
