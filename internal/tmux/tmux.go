// Package tmux wraps the tmux CLI for session/window/pane management.
// All commands target the dedicated pmux socket: tmux -L pmux.
package tmux

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
)

const (
	// defaultCommandTimeout is the default timeout for tmux CLI commands.
	// Most commands complete in milliseconds; this prevents zombie processes
	// from accumulating if tmux hangs.
	defaultCommandTimeout = 10 * time.Second

	// serverCheckTimeout is the timeout specifically for IsServerRunning checks.
	// This is shorter because it's called frequently in the monitoring loop.
	serverCheckTimeout = 5 * time.Second
)

// DefaultSocket is the tmux socket name used by pmux.
const DefaultSocket = "pmux"

// Client wraps the tmux CLI, targeting the dedicated pmux socket.
type Client struct {
	Socket string // Socket name (default: "pmux")
	TmuxBin string // Path to tmux binary (default: "tmux")
}

// NewClient creates a tmux client targeting the given socket.
// It resolves the tmux binary to an absolute path so the client works
// correctly inside launchd/systemd services where PATH is minimal.
func NewClient(socket string) *Client {
	if socket == "" {
		socket = DefaultSocket
	}
	tmuxBin := "tmux"
	if abs, err := exec.LookPath("tmux"); err == nil {
		tmuxBin = abs
	}
	return &Client{
		Socket:  socket,
		TmuxBin: tmuxBin,
	}
}

// run executes a tmux command with the pmux socket and the default timeout.
// Uses exec.CommandContext to prevent zombie tmux processes from accumulating.
func (c *Client) run(args ...string) (string, error) {
	return c.runCtx(context.Background(), defaultCommandTimeout, args...)
}

// runCtx executes a tmux command with the pmux socket using the given
// context and timeout. The timeout is applied as a context deadline on top
// of any existing deadline in ctx.
func (c *Client) runCtx(ctx context.Context, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	fullArgs := append([]string{"-L", c.Socket}, args...)
	cmd := exec.CommandContext(ctx, c.TmuxBin, fullArgs...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return strings.TrimRight(string(out), "\n"), fmt.Errorf("tmux command timed out after %s: %v", timeout, args)
	}
	return strings.TrimRight(string(out), "\n"), err
}

// IsServerRunning checks if the tmux server on the pmux socket is alive.
// Uses a 5-second timeout to prevent blocking the monitoring loop if tmux hangs.
func (c *Client) IsServerRunning() bool {
	_, err := c.runCtx(context.Background(), serverCheckTimeout, "has-session")
	return err == nil
}

// Version returns the tmux version string.
func (c *Client) Version() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, c.TmuxBin, "-V")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("tmux not available: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ListSessions returns all sessions on the pmux socket.
func (c *Client) ListSessions() ([]protocol.TmuxSession, error) {
	// Format: session_id|session_name|session_created|session_last_activity|session_attached
	format := "#{session_id}|#{session_name}|#{session_created}|#{session_last_activity}|#{session_attached}"
	out, err := c.run("list-sessions", "-F", format)
	if err != nil {
		// "no server running" or "no sessions" is not an error — return empty.
		// Also treat empty output with an error as "no sessions" — this can
		// happen when the tmux server has just exited.
		if strings.Contains(out, "no server running") ||
			strings.Contains(out, "no sessions") ||
			strings.TrimSpace(out) == "" {
			return nil, nil
		}
		return nil, fmt.Errorf("list-sessions: %w: %s", err, out)
	}

	if out == "" {
		return nil, nil
	}

	var sessions []protocol.TmuxSession
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, "|", 5)
		if len(parts) != 5 {
			continue
		}
		created, _ := strconv.ParseInt(parts[2], 10, 64)
		lastActivity, _ := strconv.ParseInt(parts[3], 10, 64)
		attached := parts[4] == "1"

		sessions = append(sessions, protocol.TmuxSession{
			ID:           parts[0],
			Name:         parts[1],
			Created:      created,
			LastActivity: lastActivity,
			Attached:     attached,
		})
	}
	return sessions, nil
}

// ListWindows returns all windows for a given session.
func (c *Client) ListWindows(sessionID string) ([]protocol.TmuxWindow, error) {
	// Format: window_id|window_name|window_index|window_active
	format := "#{window_id}|#{window_name}|#{window_index}|#{window_active}"
	out, err := c.run("list-windows", "-t", sessionID, "-F", format)
	if err != nil {
		return nil, fmt.Errorf("list-windows: %w: %s", err, out)
	}

	if out == "" {
		return nil, nil
	}

	var windows []protocol.TmuxWindow
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, "|", 4)
		if len(parts) != 4 {
			continue
		}
		index, _ := strconv.Atoi(parts[2])
		active := parts[3] == "1"

		windows = append(windows, protocol.TmuxWindow{
			ID:     parts[0],
			Name:   parts[1],
			Index:  index,
			Active: active,
		})
	}
	return windows, nil
}

// ListPanes returns all panes for a given window target (e.g. "$1:@0").
func (c *Client) ListPanes(windowTarget string) ([]protocol.TmuxPane, error) {
	// Format: pane_id|pane_index|pane_active|pane_width|pane_height|pane_title|pane_current_command
	format := "#{pane_id}|#{pane_index}|#{pane_active}|#{pane_width}|#{pane_height}|#{pane_title}|#{pane_current_command}"
	out, err := c.run("list-panes", "-t", windowTarget, "-F", format)
	if err != nil {
		return nil, fmt.Errorf("list-panes: %w: %s", err, out)
	}

	if out == "" {
		return nil, nil
	}

	var panes []protocol.TmuxPane
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, "|", 7)
		if len(parts) != 7 {
			continue
		}
		index, _ := strconv.Atoi(parts[1])
		active := parts[2] == "1"
		cols, _ := strconv.Atoi(parts[3])
		rows, _ := strconv.Atoi(parts[4])

		panes = append(panes, protocol.TmuxPane{
			ID:             parts[0],
			Index:          index,
			Active:         active,
			Size:           protocol.PaneSize{Cols: cols, Rows: rows},
			Title:          parts[5],
			CurrentCommand: parts[6],
		})
	}
	return panes, nil
}

// ListAll returns the full session tree (sessions → windows → panes).
func (c *Client) ListAll() ([]protocol.TmuxSession, error) {
	sessions, err := c.ListSessions()
	if err != nil {
		return nil, err
	}

	for i := range sessions {
		windows, err := c.ListWindows(sessions[i].ID)
		if err != nil {
			return nil, fmt.Errorf("list windows for session %s: %w", sessions[i].ID, err)
		}

		for j := range windows {
			panes, err := c.ListPanes(sessions[i].ID + ":" + windows[j].ID)
			if err != nil {
				return nil, fmt.Errorf("list panes for window %s: %w", windows[j].ID, err)
			}
			windows[j].Panes = panes
		}
		sessions[i].Windows = windows
	}

	return sessions, nil
}

// CreateSession creates a new detached tmux session.
// Returns the session ID (e.g. "$0").
func (c *Client) CreateSession(name string, command string) (string, error) {
	args := []string{"new-session", "-d", "-P", "-F", "#{session_id}"}
	if name != "" {
		args = append(args, "-s", name)
	}
	if command != "" {
		args = append(args, command)
	}

	out, err := c.run(args...)
	if err != nil {
		return "", fmt.Errorf("new-session: %w: %s", err, out)
	}
	return strings.TrimSpace(out), nil
}

// KillSession kills a tmux session by ID or name.
func (c *Client) KillSession(session string) error {
	out, err := c.run("kill-session", "-t", session)
	if err != nil {
		return fmt.Errorf("kill-session: %w: %s", err, out)
	}
	return nil
}

// ResizePane resizes a tmux pane to the given dimensions.
// For a single-pane window, use ResizeWindow instead (pane fills window).
func (c *Client) ResizePane(paneID string, cols, rows int) error {
	out, err := c.run("resize-pane", "-t", paneID, "-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows))
	if err != nil {
		return fmt.Errorf("resize-pane: %w: %s", err, out)
	}
	return nil
}

// ResizeWindow resizes a tmux window to the given dimensions.
// This is the preferred way to resize when a mobile client connects,
// as the single pane fills the entire window.
func (c *Client) ResizeWindow(windowTarget string, cols, rows int) error {
	out, err := c.run("resize-window", "-t", windowTarget, "-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows))
	if err != nil {
		return fmt.Errorf("resize-window: %w: %s", err, out)
	}
	return nil
}

// ResizeWindowAuto tells tmux to auto-adjust a window to fit the currently
// attached clients. When no mobile is connected, this restores the window
// to the local terminal's size. Uses the -A flag of resize-window.
func (c *Client) ResizeWindowAuto(windowTarget string) error {
	out, err := c.run("resize-window", "-A", "-t", windowTarget)
	if err != nil {
		return fmt.Errorf("resize-window -A: %w: %s", err, out)
	}
	return nil
}

// SendKeys sends literal input to a tmux pane using the -l flag.
// Null bytes are stripped because execve truncates argv strings at \x00,
// which would silently discard trailing input.
func (c *Client) SendKeys(paneID string, data []byte) error {
	clean := bytes.ReplaceAll(data, []byte{0}, nil)
	if len(clean) == 0 {
		return nil
	}
	out, err := c.run("send-keys", "-t", paneID, "-l", string(clean))
	if err != nil {
		return fmt.Errorf("send-keys: %w: %s", err, out)
	}
	return nil
}

// CapturePane captures the current content of a tmux pane.
// The -e flag preserves escape sequences and -p prints to stdout.
func (c *Client) CapturePane(paneID string) (string, error) {
	out, err := c.run("capture-pane", "-t", paneID, "-e", "-p")
	if err != nil {
		return "", fmt.Errorf("capture-pane: %w: %s", err, out)
	}
	return out, nil
}
