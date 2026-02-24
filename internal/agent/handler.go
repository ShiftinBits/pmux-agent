package agent

import (
	"log/slog"
	"sync"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

// SendFunc sends a protocol message to a specific peer.
type SendFunc func(peerID string, msg protocol.Message) error

// BroadcastRawFunc sends raw pre-encoded bytes to all connected peers.
type BroadcastRawFunc func(data []byte)

// Handler processes protocol messages from mobile clients and dispatches
// them to the appropriate tmux operations.
type Handler struct {
	tmux         *tmux.Client
	sizeTracker  *tmux.PaneSizeTracker
	send         SendFunc
	broadcastRaw BroadcastRawFunc
	logger       *slog.Logger

	mu          sync.Mutex
	bridges     map[string]*tmux.PaneBridge // per-peer attached bridge
	paneForPeer map[string]string           // peerID -> paneID (for restore on detach)
}

// NewHandler creates a protocol message handler.
func NewHandler(tmuxClient *tmux.Client, send SendFunc, broadcastRaw BroadcastRawFunc, logger *slog.Logger) *Handler {
	return &Handler{
		tmux:         tmuxClient,
		sizeTracker:  tmux.NewPaneSizeTracker(tmuxClient),
		send:         send,
		broadcastRaw: broadcastRaw,
		logger:       logger,
		bridges:      make(map[string]*tmux.PaneBridge),
		paneForPeer:  make(map[string]string),
	}
}

// BroadcastEmptySessions encodes a SessionsEvent with an empty session list
// and sends it to all connected peers. Used during graceful shutdown to notify
// mobile clients that the tmux server has exited.
func (h *Handler) BroadcastEmptySessions() {
	msg := &protocol.SessionsEvent{
		Type:     "sessions",
		Sessions: []protocol.TmuxSession{},
	}

	data, err := protocol.Encode(msg)
	if err != nil {
		h.logger.Error("failed to encode empty sessions event", "error", err)
		return
	}

	h.logger.Info("broadcasting empty sessions to all peers")
	h.broadcastRaw(data)
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
	case *protocol.CreateSessionRequest:
		h.handleCreateSession(peerID, m)
	case *protocol.KillSessionRequest:
		h.handleKillSession(peerID, m)
	default:
		h.logger.Warn("unknown message type", "type", msg.MessageType(), "peer", peerID)
	}
}

// PeerDisconnected cleans up state when a peer disconnects.
func (h *Handler) PeerDisconnected(peerID string) {
	h.detachPeer(peerID)
}

func (h *Handler) handleListSessions(peerID string) {
	sessions, err := h.tmux.ListAll()
	if err != nil {
		h.sendError(peerID, "list_sessions_failed", err.Error())
		return
	}

	h.sendMsg(peerID, &protocol.SessionsEvent{
		Type:     "sessions",
		Sessions: sessions,
	})
}

func (h *Handler) handleAttach(peerID string, req *protocol.AttachRequest) {
	// Detach from any existing pane first
	h.detachPeer(peerID)

	// Save original size and resize for mobile.
	// On success, pass 0,0 to AttachPane so it skips its redundant resize.
	// On failure, pass the real dimensions so AttachPane resizes as fallback.
	attachCols, attachRows := req.Cols, req.Rows
	if err := h.sizeTracker.SaveAndResize(req.PaneID, req.Cols, req.Rows); err != nil {
		h.logger.Warn("failed to save/resize pane", "error", err, "pane", req.PaneID)
	} else {
		attachCols, attachRows = 0, 0
	}

	bridge, err := h.tmux.AttachPane(req.PaneID, attachCols, attachRows)
	if err != nil {
		h.sendError(peerID, "attach_failed", err.Error())
		return
	}

	h.mu.Lock()
	h.bridges[peerID] = bridge
	h.paneForPeer[peerID] = req.PaneID
	h.mu.Unlock()

	// Send attached confirmation
	h.sendMsg(peerID, &protocol.AttachedEvent{
		Type:   "attached",
		PaneID: req.PaneID,
	})

	// Send initial pane content
	if initial := bridge.InitialContent(); initial != "" {
		h.sendMsg(peerID, &protocol.OutputEvent{
			Type: "output",
			Data: []byte(initial),
		})
	}

	// Start streaming output in background
	go h.streamOutput(peerID, bridge)
}

func (h *Handler) handleDetach(peerID string) {
	h.detachPeer(peerID)
	h.sendMsg(peerID, &protocol.DetachedEvent{Type: "detached"})
}

func (h *Handler) handleInput(peerID string, req *protocol.InputRequest) {
	h.mu.Lock()
	bridge := h.bridges[peerID]
	h.mu.Unlock()

	if bridge == nil {
		h.sendError(peerID, "not_attached", "no pane attached")
		return
	}

	if _, err := bridge.Write(req.Data); err != nil {
		h.sendError(peerID, "input_failed", err.Error())
	}
}

func (h *Handler) handleResize(peerID string, req *protocol.ResizeRequest) {
	h.mu.Lock()
	bridge := h.bridges[peerID]
	h.mu.Unlock()

	if bridge == nil {
		h.sendError(peerID, "not_attached", "no pane attached")
		return
	}

	if err := bridge.Resize(req.Cols, req.Rows); err != nil {
		h.sendError(peerID, "resize_failed", err.Error())
	}
}

func (h *Handler) handlePing(peerID string) {
	// Latency is measured by the mobile client (ping send time → pong receive time).
	// The agent responds immediately; the Latency field is unused on the agent side.
	h.sendMsg(peerID, &protocol.PongEvent{
		Type:    "pong",
		Latency: 0,
	})
}

func (h *Handler) handleCreateSession(peerID string, req *protocol.CreateSessionRequest) {
	name := ""
	if req.Name != nil {
		name = *req.Name
	}
	command := ""
	if req.Command != nil {
		command = *req.Command
	}

	sessionID, err := h.tmux.CreateSession(name, command)
	if err != nil {
		h.sendError(peerID, "create_session_failed", err.Error())
		return
	}

	h.sendMsg(peerID, &protocol.SessionCreatedEvent{
		Type:    "session_created",
		Session: sessionID,
		Name:    name,
	})
}

func (h *Handler) handleKillSession(peerID string, req *protocol.KillSessionRequest) {
	if err := h.tmux.KillSession(req.Session); err != nil {
		h.sendError(peerID, "kill_session_failed", err.Error())
		return
	}

	h.sendMsg(peerID, &protocol.SessionEndedEvent{
		Type:    "session_ended",
		Session: req.Session,
	})
}

// streamOutput reads from a PaneBridge and sends output events to the peer.
// Exits when the bridge is closed or sending fails.
func (h *Handler) streamOutput(peerID string, bridge *tmux.PaneBridge) {
	buf := make([]byte, 4096)
	for {
		n, err := bridge.Read(buf)
		if err != nil {
			return
		}

		// Copy data since buf is reused
		data := make([]byte, n)
		copy(data, buf[:n])

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

// detachPeer closes any existing bridge for a peer and restores the
// original pane size if this was the last mobile client attached.
func (h *Handler) detachPeer(peerID string) {
	h.mu.Lock()
	bridge, ok := h.bridges[peerID]
	paneID := h.paneForPeer[peerID]
	if ok {
		delete(h.bridges, peerID)
		delete(h.paneForPeer, peerID)
	}
	h.mu.Unlock()

	if ok {
		bridge.Close()
	}

	// Restore original pane size if this was the last mobile attached
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
	h.sendMsg(peerID, &protocol.ErrorEvent{
		Type:    "error",
		Code:    code,
		Message: message,
	})
}
