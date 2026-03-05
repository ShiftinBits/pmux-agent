// Package tmux wraps the tmux CLI for session/window/pane management.
// All commands target the dedicated pmux socket: tmux -L pmux.
package tmux

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
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

// ValidTmuxTarget matches tmux pane/session/window IDs like %0, $1, @2,
// $1:@2.%3, session-name, etc. Rejects shell metacharacters.
var ValidTmuxTarget = regexp.MustCompile(`^[a-zA-Z0-9_.$@:%\-]+$`)

// ErrInvalidTarget is returned when a tmux target ID contains invalid characters.
var ErrInvalidTarget = errors.New("invalid tmux target")

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

// validateTarget checks that a tmux target string is safe for CLI use.
func validateTarget(target string) error {
	if !ValidTmuxTarget.MatchString(target) {
		return fmt.Errorf("%w: %q", ErrInvalidTarget, target)
	}
	return nil
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
		if strings.Contains(out, "no server running") ||
			strings.Contains(out, "no sessions") {
			return nil, nil
		}
		// Empty output with an exit error means tmux exited with no message
		// (e.g., server just stopped). Other error types (binary missing,
		// permission denied) should propagate.
		var exitErr *exec.ExitError
		if strings.TrimSpace(out) == "" && errors.As(err, &exitErr) {
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
	if err := validateTarget(sessionID); err != nil {
		return nil, fmt.Errorf("list-windows: %w", err)
	}

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
	if err := validateTarget(windowTarget); err != nil {
		return nil, fmt.Errorf("list-panes: %w", err)
	}

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

// ResizeWindow resizes a tmux window to the given dimensions.
func (c *Client) ResizeWindow(windowTarget string, cols, rows int) error {
	out, err := c.run("resize-window", "-t", windowTarget, "-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows))
	if err != nil {
		return fmt.Errorf("resize-window: %w: %s", err, out)
	}
	return nil
}

// ResizeWindowAuto tells tmux to auto-adjust a window to fit the currently
// attached clients. Uses the -A flag of resize-window.
func (c *Client) ResizeWindowAuto(windowTarget string) error {
	out, err := c.run("resize-window", "-A", "-t", windowTarget)
	if err != nil {
		return fmt.Errorf("resize-window -A: %w: %s", err, out)
	}
	return nil
}

// ResizePane resizes a specific pane to the given dimensions.
// For multi-pane windows, only the target pane is resized and other panes
// in the same window adjust to fill remaining space.
// For single-pane windows, the containing window is resized instead
// (since the pane fills the window and resize-pane alone cannot shrink it).
func (c *Client) ResizePane(paneID string, cols, rows int) error {
	if err := validateTarget(paneID); err != nil {
		return fmt.Errorf("resize-pane: %w", err)
	}

	count, err := c.windowPaneCount(paneID)
	if err != nil {
		return fmt.Errorf("resize-pane: %w", err)
	}

	if count <= 1 {
		// Single pane fills window — resize-pane can't shrink below window size,
		// so resize the window directly.
		wt, err := c.windowForPane(paneID)
		if err != nil {
			return fmt.Errorf("resize-pane: %w", err)
		}
		return c.ResizeWindow(wt, cols, rows)
	}

	out, err := c.run("resize-pane", "-t", paneID, "-x", strconv.Itoa(cols), "-y", strconv.Itoa(rows))
	if err != nil {
		return fmt.Errorf("resize-pane: %w: %s", err, out)
	}
	return nil
}

// windowPaneCount returns the number of panes in the window containing the given pane.
func (c *Client) windowPaneCount(paneID string) (int, error) {
	out, err := c.run("display-message", "-t", paneID, "-p", "#{window_panes}")
	if err != nil {
		return 0, fmt.Errorf("window pane count: %w: %s", err, out)
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("window pane count: parse error: %q", out)
	}
	return n, nil
}

// PaneDimensions returns the current (cols, rows) of a pane.
func (c *Client) PaneDimensions(paneID string) (int, int, error) {
	if err := validateTarget(paneID); err != nil {
		return 0, 0, fmt.Errorf("pane-dimensions: %w", err)
	}
	out, err := c.run("display-message", "-t", paneID, "-p", "#{pane_width}:#{pane_height}")
	if err != nil {
		return 0, 0, fmt.Errorf("pane-dimensions: %w: %s", err, out)
	}
	parts := strings.SplitN(strings.TrimSpace(out), ":", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("pane-dimensions: unexpected output: %q", out)
	}
	cols, err1 := strconv.Atoi(parts[0])
	rows, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("pane-dimensions: parse error: %q", out)
	}
	return cols, rows, nil
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

// PaneExists returns true if a pane with the given ID exists in the tmux server.
func (c *Client) PaneExists(paneID string) bool {
	out, err := c.run("display-message", "-t", paneID, "-p", "#{pane_id}")
	if err != nil {
		return false
	}
	return strings.TrimSpace(out) == paneID
}
