package agent

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
	"github.com/shiftinbits/pmux-agent/internal/update"
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

// SendFunc sends a protocol message to a specific peer.
type SendFunc func(peerID string, msg protocol.Message) error

// Handler processes protocol messages from mobile clients and dispatches
// them to the appropriate tmux operations.
type Handler struct {
	tmux            *tmux.Client
	sizeTracker     *tmux.PaneSizeTracker
	send            SendFunc
	logger          *slog.Logger
	ctx             context.Context // agent lifecycle context
	agentVersion    string          // version string for protocol responses
	updateStateFile string          // path to update-state.json for update notifications

	mu           sync.Mutex
	bridges      map[string]*tmux.PaneBridge              // per-peer attached bridge
	cancels      map[string]context.CancelFunc             // per-peer streamOutput cancel
	paneForPeer  map[string]string                        // peerID -> paneID (for restore on detach)
	lastPingTime map[string]time.Time                     // peerID -> last ping received
	lastDims     map[string][2]int                        // peerID -> [cols, rows] to skip redundant resizes
	compressors  map[string]*protocol.OutputCompressor    // per-peer stateful deflate compressor
}

// NewHandler creates a protocol message handler.
func NewHandler(tmuxClient *tmux.Client, send SendFunc, logger *slog.Logger, agentVersion, updateStateFile string) *Handler {
	return &Handler{
		tmux:            tmuxClient,
		sizeTracker:     tmux.NewPaneSizeTracker(tmuxClient),
		send:            send,
		logger:          logger,
		agentVersion:    agentVersion,
		updateStateFile: updateStateFile,
		ctx:             context.Background(), // overridden by SetContext in agent.go
		bridges:      make(map[string]*tmux.PaneBridge),
		cancels:      make(map[string]context.CancelFunc),
		paneForPeer:  make(map[string]string),
		lastPingTime: make(map[string]time.Time),
		lastDims:     make(map[string][2]int),
		compressors:  make(map[string]*protocol.OutputCompressor),
	}
}

// SetContext sets the agent lifecycle context for deriving per-peer contexts.
// Called by agent.Run() after creating the cancelable agent context.
func (h *Handler) SetContext(ctx context.Context) {
	h.mu.Lock()
	h.ctx = ctx
	h.mu.Unlock()
}

// newSessionsEvent builds a SessionsEvent with agent version and update info populated.
func (h *Handler) newSessionsEvent(sessions []protocol.TmuxSession) *protocol.SessionsEvent {
	event := &protocol.SessionsEvent{
		Type:         "sessions",
		Sessions:     sessions,
		AgentVersion: h.agentVersion,
	}
	if h.updateStateFile != "" {
		if state, err := update.LoadState(h.updateStateFile); err == nil && state.UpdateAvailable {
			event.UpdateAvailable = state.LatestVersion
		}
	}
	return event
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

	// Safety net: if the peer is attached to a pane that no longer exists
	// in the session tree, send pane_closed before the sessions response.
	// This catches cases where the pane closed during a connection gap and
	// watchPane was killed by context cancellation before detecting it.
	h.mu.Lock()
	attachedPane := h.paneForPeer[peerID]
	h.mu.Unlock()

	if attachedPane != "" {
		found := false
		for _, s := range sessions {
			for _, w := range s.Windows {
				for _, p := range w.Panes {
					if p.ID == attachedPane {
						found = true
						break
					}
				}
				if found {
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			h.logger.Info("attached pane missing from session tree, sending pane_closed",
				"peer", peerID, "pane", attachedPane)
			h.sendMsg(peerID, &protocol.PaneClosedEvent{
				Type:   "pane_closed",
				PaneID: attachedPane,
			})
			h.detachPeer(peerID)
		}
	}

	if err := h.sendMsg(peerID, h.newSessionsEvent(toProtocolSessions(sessions))); err != nil {
		h.logger.Warn("failed to send sessions event", "peer", peerID, "error", err)
	}
}

func (h *Handler) handleAttach(peerID string, req *protocol.AttachRequest) {
	h.logger.Debug("attach requested", "peer", peerID, "pane", req.PaneID, "reattach", req.Reattach)

	// Validate pane ID format before passing to tmux CLI.
	if !tmux.ValidTmuxTarget.MatchString(req.PaneID) {
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

	// Resize the pane's window to mobile dimensions BEFORE opening the bridge.
	// This ensures the SIGWINCH re-render happens while pipe-pane is NOT active,
	// so the escape-sequence-heavy re-render (with cursor positioning relative
	// to the computer's terminal state) is discarded. The shell ends up at the
	// correct mobile width, and all future output via pipe-pane will be rendered
	// at that width without staircase artifacts.
	sizeTracked := false
	if err := h.sizeTracker.TrackAndResize(req.PaneID, req.Cols, req.Rows); err != nil {
		h.logger.Warn("failed to track/resize pane", "error", err, "pane", req.PaneID)
	} else {
		sizeTracked = true
	}

	bridge, err := h.tmux.AttachPane(req.PaneID, 0, 0)
	if err != nil {
		h.logger.Debug("attach pane failed", "peer", peerID, "pane", req.PaneID, "error", err)

		// Undo size tracking if we resized but couldn't attach.
		if sizeTracked {
			if restoreErr := h.sizeTracker.RestoreIfLast(req.PaneID); restoreErr != nil {
				h.logger.Warn("failed to restore pane size after attach failure", "error", restoreErr)
			}
		}

		// If the pane no longer exists, send pane_closed + fresh sessions
		// instead of a generic attach_failed. This handles the case where a
		// pane closed during a connection gap and the mobile tries to re-attach.
		if !h.tmux.PaneExists(req.PaneID) {
			h.logger.Info("pane no longer exists on attach attempt, sending pane_closed", "peer", peerID, "pane", req.PaneID)
			h.sendMsg(peerID, &protocol.PaneClosedEvent{
				Type:   "pane_closed",
				PaneID: req.PaneID,
			})
			if sessions, listErr := h.tmux.ListAll(); listErr == nil {
				h.sendMsg(peerID, h.newSessionsEvent(toProtocolSessions(sessions)))
			}
			return
		}

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
	h.lastDims[peerID] = [2]int{req.Cols, req.Rows}
	h.mu.Unlock()

	// Build attached event — echo compression if negotiated
	attachedEvent := &protocol.AttachedEvent{
		Type:   "attached",
		PaneID: req.PaneID,
	}
	if req.Compression == "deflate" {
		compressor := protocol.NewOutputCompressor()
		h.mu.Lock()
		h.compressors[peerID] = compressor
		h.mu.Unlock()
		attachedEvent.Compression = "deflate"
	}
	h.sendMsg(peerID, attachedEvent)

	// Synchronize terminal mode state with xterm.js on the mobile.
	// pipe-pane only captures output AFTER it starts — mode-setting sequences
	// the pane's program sent earlier (alternate screen, cursor hide) are lost.
	// Query tmux for the pane's current mode state and send restoration
	// sequences before any pipe-pane output reaches the mobile.
	cursorState, csErr := h.tmux.CursorState(req.PaneID)
	if csErr != nil {
		h.logger.Debug("cursor state query failed, skipping mode sync", "peer", peerID, "error", csErr)
	}

	// Build mode restoration prefix: alternate screen + cursor visibility.
	var modePrefix []byte
	if csErr == nil && cursorState.AlternateOn {
		modePrefix = append(modePrefix, "\x1b[?1049h"...)
	}

	// Skip initial capture-pane content on fresh attach — the captured buffer
	// contains prompts reflowed from the computer's wider terminal, producing
	// staircase indentation. The shell is already at the correct mobile width
	// (resized above), so all new output via pipe-pane will render correctly.
	// On reattach, send initial content so the mobile can restore its buffer.
	if req.Reattach {
		if initial := bridge.InitialContent(); initial != "" {
			// Prepend mode restoration (alt screen) and append cursor
			// position + visibility so xterm.js matches tmux's state.
			initialData := make([]byte, 0, len(modePrefix)+len(initial)+32)
			initialData = append(initialData, modePrefix...)
			initialData = append(initialData, []byte(initial)...)
			if csErr == nil {
				initialData = fmt.Appendf(initialData,
					"\x1b[%d;%dH", cursorState.CursorY+1, cursorState.CursorX+1)
				if !cursorState.CursorVisible {
					initialData = append(initialData, "\x1b[?25l"...)
				}
			}
			h.mu.Lock()
			compressor := h.compressors[peerID]
			h.mu.Unlock()
			if compressor != nil {
				if compressed, err := compressor.Compress(initialData); err == nil {
					initialData = compressed
				} else {
					h.logger.Warn("failed to compress initial content", "peer", peerID, "error", err)
				}
			}
			h.sendMsg(peerID, &protocol.OutputEvent{
				Type: "output",
				Data: initialData,
			})
		}
	} else if csErr == nil && (cursorState.AlternateOn || !cursorState.CursorVisible) {
		// Fresh attach: send mode state so xterm.js enters the correct
		// terminal mode before pipe-pane output arrives.
		stateData := make([]byte, 0, 32)
		stateData = append(stateData, modePrefix...)
		if !cursorState.CursorVisible {
			stateData = append(stateData, "\x1b[?25l"...)
		}
		h.mu.Lock()
		compressor := h.compressors[peerID]
		h.mu.Unlock()
		if compressor != nil {
			if compressed, err := compressor.Compress(stateData); err == nil {
				stateData = compressed
			}
		}
		h.sendMsg(peerID, &protocol.OutputEvent{
			Type: "output",
			Data: stateData,
		})
	}

	// Start streaming output in background with context for lifecycle management
	go h.streamOutput(ctx, peerID, bridge)

	// Start pane existence watcher — detects pane closure when the process exits
	go h.watchPane(ctx, peerID, req.PaneID)
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
	last := h.lastDims[peerID]
	h.mu.Unlock()

	if bridge == nil {
		h.sendError(peerID, "not_attached", "no pane attached")
		return
	}

	// Skip resize when dimensions are unchanged to avoid unnecessary
	// tmux resize-window calls and SIGWINCH signals.
	if last[0] == req.Cols && last[1] == req.Rows {
		return
	}

	if err := bridge.Resize(req.Cols, req.Rows); err != nil {
		h.logger.Debug("resize failed", "peer", peerID, "error", err)
		h.sendError(peerID, "resize_failed", "failed to resize pane")
		return
	}

	h.mu.Lock()
	h.lastDims[peerID] = [2]int{req.Cols, req.Rows}
	h.mu.Unlock()
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
	if !tmux.ValidTmuxTarget.MatchString(req.Session) {
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
// When the bridge returns EOF (pane exited), sends pane_closed + sessions events.
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
			// Distinguish between context cancellation and pane exit (EOF)
			if ctx.Err() != nil {
				h.logger.Debug("streamOutput stopped by context", "peer", peerID)
				return
			}
			// Pane exited — notify mobile and clean up
			h.handlePaneExit(peerID)
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

		// Compress output data if compression is active for this peer
		h.mu.Lock()
		compressor := h.compressors[peerID]
		h.mu.Unlock()

		if compressor != nil {
			compressed, err := compressor.Compress(data)
			if err != nil {
				h.logger.Warn("output compression failed, disabling for peer",
					"peer", peerID, "error", err)
				h.mu.Lock()
				if c := h.compressors[peerID]; c != nil {
					c.Close()
					delete(h.compressors, peerID)
				}
				h.mu.Unlock()
				// Fall through to send uncompressed data
			} else {
				data = compressed
			}
		}

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

// handlePaneExit is called when streamOutput detects that a pane has exited.
// It sends a pane_closed event followed by a fresh sessions tree, then cleans up.
func (h *Handler) handlePaneExit(peerID string) {
	h.mu.Lock()
	paneID := h.paneForPeer[peerID]
	h.mu.Unlock()

	if paneID == "" {
		return
	}

	h.logger.Info("pane exited, notifying peer", "peer", peerID, "pane", paneID)

	// Send pane_closed event
	if err := h.sendMsg(peerID, &protocol.PaneClosedEvent{
		Type:   "pane_closed",
		PaneID: paneID,
	}); err != nil {
		h.logger.Error("failed to send pane_closed", "peer", peerID, "pane", paneID, "error", err)
	} else {
		h.logger.Info("sent pane_closed", "peer", peerID, "pane", paneID)
	}

	// Send fresh session tree so mobile can navigate to the new active pane
	sessions, err := h.tmux.ListAll()
	if err != nil {
		h.logger.Warn("failed to list sessions after pane close", "error", err)
	} else {
		if err := h.sendMsg(peerID, h.newSessionsEvent(toProtocolSessions(sessions))); err != nil {
			h.logger.Error("failed to send sessions after pane close", "peer", peerID, "error", err)
		} else {
			h.logger.Info("sent sessions after pane close", "peer", peerID, "sessionCount", len(sessions))
		}
	}

	// Clean up bridge and state
	h.detachPeer(peerID)
}

// watchPane periodically checks whether the attached pane still exists in tmux.
// When the pane is gone (process exited, session killed, etc.), it triggers
// handlePaneExit to notify the mobile client. This is needed because the
// PaneBridge FIFO uses O_RDWR and never returns EOF on pane closure.
func (h *Handler) watchPane(ctx context.Context, peerID, paneID string) {
	h.logger.Debug("watchPane started", "peer", peerID, "pane", paneID)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			h.logger.Debug("watchPane stopped (context canceled)", "peer", peerID, "pane", paneID)
			return
		case <-ticker.C:
			if !h.tmux.PaneExists(paneID) {
				h.logger.Info("watchPane: pane no longer exists, triggering handlePaneExit", "peer", peerID, "pane", paneID)
				h.handlePaneExit(peerID)
				return
			}
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
	compressor := h.compressors[peerID]
	if ok {
		delete(h.bridges, peerID)
		delete(h.cancels, peerID)
		delete(h.paneForPeer, peerID)
		delete(h.lastDims, peerID)
		delete(h.compressors, peerID)
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

	if compressor != nil {
		compressor.Close()
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

// toProtocolSessions converts tmux domain types to protocol wire types.
func toProtocolSessions(sessions []tmux.Session) []protocol.TmuxSession {
	result := make([]protocol.TmuxSession, len(sessions))
	for i, s := range sessions {
		result[i] = protocol.TmuxSession{
			ID:             s.ID,
			Name:           s.Name,
			CreatedAt:      s.CreatedAt,
			LastActivityAt: s.LastActivityAt,
			Attached:       s.Attached,
			Windows:        toProtocolWindows(s.Windows),
		}
	}
	return result
}

func toProtocolWindows(windows []tmux.Window) []protocol.TmuxWindow {
	result := make([]protocol.TmuxWindow, len(windows))
	for i, w := range windows {
		result[i] = protocol.TmuxWindow{
			ID:     w.ID,
			Name:   w.Name,
			Index:  w.Index,
			Active: w.Active,
			Panes:  toProtocolPanes(w.Panes),
		}
	}
	return result
}

func toProtocolPanes(panes []tmux.Pane) []protocol.TmuxPane {
	result := make([]protocol.TmuxPane, len(panes))
	for i, p := range panes {
		result[i] = protocol.TmuxPane{
			ID:             p.ID,
			Index:          p.Index,
			Active:         p.Active,
			Size:           protocol.PaneSize{Cols: p.Size.Cols, Rows: p.Size.Rows},
			Title:          p.Title,
			CurrentCommand: p.CurrentCommand,
		}
	}
	return result
}
