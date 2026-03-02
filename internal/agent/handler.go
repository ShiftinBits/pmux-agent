package agent

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

const (
	// maxResizeDimension is the upper bound for resize column/row values.
	// No real terminal exceeds 500 columns or rows.
	maxResizeDimension = 500

	// minResizeDimension is the lower bound for resize column/row values.
	minResizeDimension = 1

	// maxInputSize is the maximum allowed input request data size.
	// 16 KB is well within OS ARG_MAX limits for tmux send-keys via execve.
	maxInputSize = 16 * 1024
)

// validTmuxTarget matches tmux pane/session/window IDs like %0, $1, @2,
// $1:@2.%3, session-name, etc. Rejects shell metacharacters.
var validTmuxTarget = regexp.MustCompile(`^[a-zA-Z0-9_.$@:%\-]+$`)

// SendFunc sends a protocol message to a specific peer.
type SendFunc func(peerID string, msg protocol.Message) error

// Handler processes protocol messages from mobile clients and dispatches
// them to the appropriate tmux operations.
type Handler struct {
	tmux         *tmux.Client
	sizeTracker  *tmux.PaneSizeTracker
	send         SendFunc
	logger       *slog.Logger
	ctx          context.Context // agent lifecycle context

	mu           sync.Mutex
	bridges      map[string]*tmux.PaneBridge // per-peer attached bridge
	cancels      map[string]context.CancelFunc // per-peer streamOutput cancel
	paneForPeer  map[string]string           // peerID -> paneID (for restore on detach)
	lastPingTime map[string]time.Time        // peerID -> last ping received
}

// NewHandler creates a protocol message handler.
func NewHandler(tmuxClient *tmux.Client, send SendFunc, logger *slog.Logger) *Handler {
	return &Handler{
		tmux:         tmuxClient,
		sizeTracker:  tmux.NewPaneSizeTracker(tmuxClient),
		send:         send,
		logger:       logger,
		ctx:          context.Background(), // overridden by SetContext in agent.go
		bridges:      make(map[string]*tmux.PaneBridge),
		cancels:      make(map[string]context.CancelFunc),
		paneForPeer:  make(map[string]string),
		lastPingTime: make(map[string]time.Time),
	}
}

// SetContext sets the agent lifecycle context for deriving per-peer contexts.
// Called by agent.Run() after creating the cancelable agent context.
func (h *Handler) SetContext(ctx context.Context) {
	h.mu.Lock()
	h.ctx = ctx
	h.mu.Unlock()
}

// HandleMessage processes an incoming protocol message from a peer.
// This is the ProtocolHandler callback for the PeerManager.
func (h *Handler) HandleMessage(peerID string, msg protocol.Message) {
	h.logger.Debug("handling message", "type", msg.MessageType(), "peer", peerID)

	switch m := msg.(type) {
	case *protocol.ListSessionsRequest:
		h.handleListSessions(peerID)
	case *protocol.AttachRequest:
		h.handleAttach(peerID, m)
	case *protocol.DetachRequest:
		h.handleDetach(peerID)
	case *protocol.InputRequest:
		h.handleInput(peerID, m)
	case *protocol.ResizeRequest:
		h.handleResize(peerID, m)
	case *protocol.PingRequest:
		h.handlePing(peerID)
	case *protocol.KillSessionRequest:
		h.handleKillSession(peerID, m)
	default:
		h.logger.Warn("unknown message type", "type", msg.MessageType(), "peer", peerID)
	}
}

// PeerDisconnected cleans up state when a peer disconnects.
func (h *Handler) PeerDisconnected(peerID string) {
	h.mu.Lock()
	delete(h.lastPingTime, peerID)
	h.mu.Unlock()

	h.detachPeer(peerID)
}

// GetStalePeers returns peer IDs that have not sent a ping within the given timeout.
// A peer with no recorded ping time is not considered stale (it may not have
// connected long enough to send its first ping).
func (h *Handler) GetStalePeers(timeout time.Duration) []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	now := time.Now()
	var stale []string
	for peerID, lastPing := range h.lastPingTime {
		if now.Sub(lastPing) > timeout {
			stale = append(stale, peerID)
		}
	}
	return stale
}

func (h *Handler) handleListSessions(peerID string) {
	sessions, err := h.tmux.ListAll()
	if err != nil {
		h.logger.Debug("list sessions failed", "peer", peerID, "error", err)
		h.sendError(peerID, "list_sessions_failed", "failed to list sessions")
		return
	}

	// Log session tree summary for debugging mobile display issues.
	totalWindows, totalPanes := 0, 0
	for _, s := range sessions {
		totalWindows += len(s.Windows)
		for _, w := range s.Windows {
			totalPanes += len(w.Panes)
		}
	}
	h.logger.Debug("list_sessions response",
		"peer", peerID,
		"sessions", len(sessions),
		"windows", totalWindows,
		"panes", totalPanes,
	)

	if err := h.sendMsg(peerID, &protocol.SessionsEvent{
		Type:     "sessions",
		Sessions: sessions,
	}); err != nil {
		h.logger.Warn("failed to send sessions event", "peer", peerID, "error", err)
	}
}

func (h *Handler) handleAttach(peerID string, req *protocol.AttachRequest) {
	// Validate pane ID format before passing to tmux CLI.
	if !validTmuxTarget.MatchString(req.PaneID) {
		h.sendError(peerID, "attach_failed", fmt.Sprintf("invalid pane ID: %q", req.PaneID))
		return
	}

	// Validate dimensions (same bounds as handleResize).
	if req.Cols < minResizeDimension || req.Cols > maxResizeDimension ||
		req.Rows < minResizeDimension || req.Rows > maxResizeDimension {
		h.sendError(peerID, "attach_failed",
			fmt.Sprintf("dimensions out of range: cols=%d rows=%d (must be %d-%d)",
				req.Cols, req.Rows, minResizeDimension, maxResizeDimension))
		return
	}

	// Detach from any existing pane first
	h.detachPeer(peerID)

	// Track attach and resize for mobile.
	// On success, pass 0,0 to AttachPane so it skips its redundant resize.
	// On failure, pass the real dimensions so AttachPane resizes as fallback.
	sizeTracked := false
	attachCols, attachRows := req.Cols, req.Rows
	if err := h.sizeTracker.TrackAndResize(req.PaneID, req.Cols, req.Rows); err != nil {
		h.logger.Warn("failed to track/resize pane", "error", err, "pane", req.PaneID)
	} else {
		attachCols, attachRows = 0, 0
		sizeTracked = true
	}

	bridge, err := h.tmux.AttachPane(req.PaneID, attachCols, attachRows)
	if err != nil {
		// Clean up size tracking if attach fails to prevent leaked state.
		if sizeTracked {
			if restoreErr := h.sizeTracker.RestoreIfLast(req.PaneID); restoreErr != nil {
				h.logger.Warn("failed to restore pane size after attach failure", "error", restoreErr, "pane", req.PaneID)
			}
		}
		h.logger.Debug("attach pane failed", "peer", peerID, "pane", req.PaneID, "error", err)
		h.sendError(peerID, "attach_failed", "failed to attach pane")
		return
	}

	// Create a per-peer context derived from the agent lifecycle context.
	// When the agent shuts down, all per-peer streams are automatically canceled.
	h.mu.Lock()
	parentCtx := h.ctx
	h.mu.Unlock()
	ctx, cancel := context.WithCancel(parentCtx)

	h.mu.Lock()
	h.bridges[peerID] = bridge
	h.cancels[peerID] = cancel
	h.paneForPeer[peerID] = req.PaneID
	h.mu.Unlock()

	// Send attached confirmation
	h.sendMsg(peerID, &protocol.AttachedEvent{
		Type:   "attached",
		PaneID: req.PaneID,
	})

	// Send initial pane content (skip on reattach — mobile already has buffer)
	if !req.Reattach {
		if initial := bridge.InitialContent(); initial != "" {
			h.sendMsg(peerID, &protocol.OutputEvent{
				Type: "output",
				Data: []byte(initial),
			})
		}
	}

	// Start streaming output in background with context for lifecycle management
	go h.streamOutput(ctx, peerID, bridge)
}

func (h *Handler) handleDetach(peerID string) {
	h.detachPeer(peerID)
	h.sendMsg(peerID, &protocol.DetachedEvent{Type: "detached"})
}

func (h *Handler) handleInput(peerID string, req *protocol.InputRequest) {
	if len(req.Data) > maxInputSize {
		h.sendError(peerID, "input_too_large",
			fmt.Sprintf("input size %d exceeds %d byte limit", len(req.Data), maxInputSize))
		return
	}

	h.mu.Lock()
	bridge := h.bridges[peerID]
	h.mu.Unlock()

	if bridge == nil {
		h.sendError(peerID, "not_attached", "no pane attached")
		return
	}

	if _, err := bridge.Write(req.Data); err != nil {
		h.logger.Debug("input write failed", "peer", peerID, "error", err)
		h.sendError(peerID, "input_failed", "failed to send input")
	}
}

func (h *Handler) handleResize(peerID string, req *protocol.ResizeRequest) {
	// Validate dimensions to prevent resource abuse or unexpected tmux behavior.
	if req.Cols < minResizeDimension || req.Cols > maxResizeDimension ||
		req.Rows < minResizeDimension || req.Rows > maxResizeDimension {
		h.sendError(peerID, "resize_failed",
			fmt.Sprintf("dimensions out of range: cols=%d rows=%d (must be %d-%d)",
				req.Cols, req.Rows, minResizeDimension, maxResizeDimension))
		return
	}

	h.mu.Lock()
	bridge := h.bridges[peerID]
	h.mu.Unlock()

	if bridge == nil {
		h.sendError(peerID, "not_attached", "no pane attached")
		return
	}

	if err := bridge.Resize(req.Cols, req.Rows); err != nil {
		h.logger.Debug("resize failed", "peer", peerID, "error", err)
		h.sendError(peerID, "resize_failed", "failed to resize pane")
	}
}

func (h *Handler) handlePing(peerID string) {
	// Record when this peer last sent a ping (for idle detection).
	h.mu.Lock()
	h.lastPingTime[peerID] = time.Now()
	h.mu.Unlock()

	// Latency is measured by the mobile client (ping send time → pong receive time).
	// The agent responds immediately; the Latency field is unused on the agent side.
	h.sendMsg(peerID, &protocol.PongEvent{
		Type:    "pong",
		Latency: 0,
	})
}

func (h *Handler) handleKillSession(peerID string, req *protocol.KillSessionRequest) {
	// Validate session ID format before passing to tmux CLI.
	if !validTmuxTarget.MatchString(req.Session) {
		h.sendError(peerID, "kill_session_failed", fmt.Sprintf("invalid session ID: %q", req.Session))
		return
	}

	if err := h.tmux.KillSession(req.Session); err != nil {
		h.logger.Debug("kill session failed", "peer", peerID, "session", req.Session, "error", err)
		h.sendError(peerID, "kill_session_failed", "failed to kill session")
		return
	}

	h.sendMsg(peerID, &protocol.SessionEndedEvent{
		Type:    "session_ended",
		Session: req.Session,
	})
}

// streamOutput reads from a PaneBridge and sends output events to the peer.
// Exits when the context is canceled, the bridge is closed, or sending fails.
func (h *Handler) streamOutput(ctx context.Context, peerID string, bridge *tmux.PaneBridge) {
	buf := make([]byte, 4096)
	filter := tmux.NewTitleFilter() // Strip tmux title escapes for xterm.js
	for {
		// Check context before blocking on Read
		if ctx.Err() != nil {
			h.logger.Debug("streamOutput context canceled", "peer", peerID)
			return
		}

		n, err := bridge.Read(buf)
		if err != nil {
			// Distinguish between context cancellation and bridge errors
			if ctx.Err() != nil {
				h.logger.Debug("streamOutput stopped by context", "peer", peerID)
			}
			return
		}

		// Strip tmux-specific ESC k ... ESC \ title sequences that
		// xterm.js does not recognize and would render as visible text.
		filtered := filter.Filter(buf[:n])
		if len(filtered) == 0 {
			continue // entire chunk was title data
		}

		// Copy data since filtered slice is reused by the filter
		data := make([]byte, len(filtered))
		copy(data, filtered)

		if err := h.sendMsg(peerID, &protocol.OutputEvent{
			Type: "output",
			Data: data,
		}); err != nil {
			h.logger.Debug("output stream send failed, stopping", "peer", peerID, "error", err)
			h.detachPeer(peerID)
			return
		}
	}
}

// detachPeer cancels the streamOutput goroutine, closes any existing bridge
// for a peer, and auto-resizes the pane window if this was the last
// mobile client attached.
func (h *Handler) detachPeer(peerID string) {
	h.mu.Lock()
	bridge, ok := h.bridges[peerID]
	cancel := h.cancels[peerID]
	paneID := h.paneForPeer[peerID]
	if ok {
		delete(h.bridges, peerID)
		delete(h.cancels, peerID)
		delete(h.paneForPeer, peerID)
	}
	h.mu.Unlock()

	// Cancel the streamOutput context first so the goroutine can exit
	// before we close the bridge underneath it.
	if cancel != nil {
		cancel()
	}

	if ok {
		bridge.Close()
	}

	// Auto-resize pane window if this was the last mobile attached
	if paneID != "" {
		if err := h.sizeTracker.RestoreIfLast(paneID); err != nil {
			h.logger.Warn("failed to restore pane size", "error", err, "pane", paneID)
		}
	}
}

func (h *Handler) sendMsg(peerID string, msg protocol.Message) error {
	if err := h.send(peerID, msg); err != nil {
		h.logger.Debug("send failed", "type", msg.MessageType(), "peer", peerID, "error", err)
		return err
	}
	return nil
}

func (h *Handler) sendError(peerID string, code string, message string) {
	if err := h.sendMsg(peerID, &protocol.ErrorEvent{
		Type:    "error",
		Code:    code,
		Message: message,
	}); err != nil {
		h.logger.Warn("failed to send error to peer",
			"peer", peerID, "code", code, "sendError", err)
	}
}
