package webrtc

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/pion/webrtc/v4"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
)

// DataChannelLabel is the name of the WebRTC DataChannel used for terminal protocol.
const DataChannelLabel = "terminal"

// TurnCredentials holds STUN/TURN server credentials from the signaling server.
type TurnCredentials struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

// MessageSender sends signaling messages (SDP/ICE) via the signaling client.
type MessageSender interface {
	Send(msg SignalingMessage) error
}

// ProtocolHandler is called when a decoded protocol message arrives on the DataChannel.
type ProtocolHandler func(peerID string, msg protocol.Message)

// PeerManager manages multiple WebRTC peer connections, one per mobile device.
type PeerManager struct {
	logger    *slog.Logger
	signaling MessageSender
	serverURL string
	jwt       func() string // returns current JWT
	handler   ProtocolHandler

	// API is the Pion WebRTC API used to create peer connections.
	// If nil, the default API is used. Set this for testing with custom settings.
	API *webrtc.API

	mu    sync.Mutex
	peers map[string]*Peer // keyed by mobile device ID
}

// Peer represents a single WebRTC peer connection to a mobile device.
type Peer struct {
	DeviceID   string
	conn       *webrtc.PeerConnection
	dc         *webrtc.DataChannel
	logger     *slog.Logger
	signaling  MessageSender
	handler    ProtocolHandler
	mu         sync.Mutex
	closed     bool
}

// NewPeerManager creates a manager for WebRTC peer connections.
func NewPeerManager(logger *slog.Logger, signaling MessageSender, serverURL string, jwtFn func() string, handler ProtocolHandler) *PeerManager {
	return &PeerManager{
		logger:    logger,
		signaling: signaling,
		serverURL: strings.TrimRight(serverURL, "/"),
		jwt:       jwtFn,
		handler:   handler,
		peers:     make(map[string]*Peer),
	}
}

// HandleSignalingMessage processes an incoming signaling message (connect_request, sdp_answer, ice_candidate).
func (pm *PeerManager) HandleSignalingMessage(msg SignalingMessage) {
	switch msg.Type {
	case "connect_request":
		pm.handleConnectRequest(msg.TargetDeviceID)
	case "sdp_answer":
		pm.handleSDPAnswer(msg.TargetDeviceID, msg.SDP)
	case "ice_candidate":
		pm.handleICECandidate(msg.TargetDeviceID, msg.Candidate, msg.SDPMid, msg.SDPMLineIndex)
	}
}

// ClosePeer closes a specific peer connection.
func (pm *PeerManager) ClosePeer(deviceID string) {
	pm.mu.Lock()
	peer, ok := pm.peers[deviceID]
	if ok {
		delete(pm.peers, deviceID)
	}
	pm.mu.Unlock()

	if ok {
		peer.Close()
	}
}

// CloseAll closes all peer connections.
func (pm *PeerManager) CloseAll() {
	pm.mu.Lock()
	peers := make([]*Peer, 0, len(pm.peers))
	for _, p := range pm.peers {
		peers = append(peers, p)
	}
	pm.peers = make(map[string]*Peer)
	pm.mu.Unlock()

	for _, p := range peers {
		p.Close()
	}
}

// SendTo sends a protocol message to a specific peer via their DataChannel.
func (pm *PeerManager) SendTo(deviceID string, msg protocol.Message) error {
	pm.mu.Lock()
	peer, ok := pm.peers[deviceID]
	pm.mu.Unlock()

	if !ok {
		return fmt.Errorf("no peer connection for device %s", deviceID)
	}

	return peer.SendMessage(msg)
}

// handleConnectRequest creates a new peer connection and SDP offer for an incoming mobile client.
func (pm *PeerManager) handleConnectRequest(mobileDeviceID string) {
	pm.logger.Info("connect_request received", "mobile", mobileDeviceID)

	// Close existing peer connection if any (re-connect scenario)
	pm.ClosePeer(mobileDeviceID)

	// Fetch TURN credentials (skipped when custom API is set, e.g. in tests)
	config := webrtc.Configuration{}
	if pm.API == nil {
		iceServers, err := pm.fetchTurnCredentials()
		if err != nil {
			pm.logger.Warn("failed to fetch TURN credentials, using STUN only", "error", err)
			iceServers = []webrtc.ICEServer{
				{URLs: []string{"stun:stun.cloudflare.com:3478"}},
			}
		}
		config.ICEServers = iceServers
	}

	var pc *webrtc.PeerConnection
	var err error
	if pm.API != nil {
		pc, err = pm.API.NewPeerConnection(config)
	} else {
		pc, err = webrtc.NewPeerConnection(config)
	}
	if err != nil {
		pm.logger.Error("failed to create peer connection", "error", err)
		return
	}

	peer := &Peer{
		DeviceID:  mobileDeviceID,
		conn:      pc,
		logger:    pm.logger.With("peer", mobileDeviceID),
		signaling: pm.signaling,
		handler:   pm.handler,
	}

	pm.mu.Lock()
	pm.peers[mobileDeviceID] = peer
	pm.mu.Unlock()

	// Set up event handlers
	peer.setupHandlers()

	// Create DataChannel
	dc, err := pc.CreateDataChannel(DataChannelLabel, &webrtc.DataChannelInit{
		Ordered: boolPtr(true),
	})
	if err != nil {
		pm.logger.Error("failed to create data channel", "error", err)
		pm.ClosePeer(mobileDeviceID)
		return
	}
	peer.dc = dc
	peer.setupDataChannelHandlers(dc)

	// Create offer
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		pm.logger.Error("failed to create SDP offer", "error", err)
		pm.ClosePeer(mobileDeviceID)
		return
	}

	if err := pc.SetLocalDescription(offer); err != nil {
		pm.logger.Error("failed to set local description", "error", err)
		pm.ClosePeer(mobileDeviceID)
		return
	}

	// Send offer via signaling
	if err := pm.signaling.Send(SignalingMessage{
		Type:           "sdp_offer",
		TargetDeviceID: mobileDeviceID,
		SDP:            offer.SDP,
	}); err != nil {
		pm.logger.Error("failed to send SDP offer", "error", err)
	}

	pm.logger.Info("SDP offer sent", "mobile", mobileDeviceID)
}

// handleSDPAnswer sets the remote description from the mobile's SDP answer.
func (pm *PeerManager) handleSDPAnswer(mobileDeviceID string, sdp string) {
	pm.mu.Lock()
	peer, ok := pm.peers[mobileDeviceID]
	pm.mu.Unlock()

	if !ok {
		pm.logger.Warn("sdp_answer for unknown peer", "mobile", mobileDeviceID)
		return
	}

	answer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  sdp,
	}

	if err := peer.conn.SetRemoteDescription(answer); err != nil {
		pm.logger.Error("failed to set remote description", "error", err, "mobile", mobileDeviceID)
		return
	}

	pm.logger.Info("SDP answer applied", "mobile", mobileDeviceID)
}

// handleICECandidate adds an ICE candidate from the mobile peer.
func (pm *PeerManager) handleICECandidate(mobileDeviceID string, candidate string, sdpMid string, sdpMLineIndex *int) {
	pm.mu.Lock()
	peer, ok := pm.peers[mobileDeviceID]
	pm.mu.Unlock()

	if !ok {
		pm.logger.Warn("ice_candidate for unknown peer", "mobile", mobileDeviceID)
		return
	}

	var mLineIndex *uint16
	if sdpMLineIndex != nil {
		v := uint16(*sdpMLineIndex)
		mLineIndex = &v
	}

	ice := webrtc.ICECandidateInit{
		Candidate:     candidate,
		SDPMid:        &sdpMid,
		SDPMLineIndex: mLineIndex,
	}

	if err := peer.conn.AddICECandidate(ice); err != nil {
		pm.logger.Warn("failed to add ICE candidate", "error", err, "mobile", mobileDeviceID)
	}
}

// fetchTurnCredentials calls the server API to get TURN credentials.
func (pm *PeerManager) fetchTurnCredentials() ([]webrtc.ICEServer, error) {
	url := pm.serverURL + "/turn/credentials"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create TURN request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pm.jwt())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("TURN credentials request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read TURN response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("TURN credentials failed (%d): %s", resp.StatusCode, string(body))
	}

	var creds TurnCredentials
	if err := json.Unmarshal(body, &creds); err != nil {
		return nil, fmt.Errorf("parse TURN credentials: %w", err)
	}

	return []webrtc.ICEServer{
		{
			URLs:       creds.URLs,
			Username:   creds.Username,
			Credential: creds.Credential,
		},
	}, nil
}

// --- Peer methods ---

// setupHandlers configures ICE and connection state handlers on the peer connection.
func (p *Peer) setupHandlers() {
	p.conn.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()

		var mLineIndex *int
		if init.SDPMLineIndex != nil {
			v := int(*init.SDPMLineIndex)
			mLineIndex = &v
		}

		var sdpMid string
		if init.SDPMid != nil {
			sdpMid = *init.SDPMid
		}

		if err := p.signaling.Send(SignalingMessage{
			Type:           "ice_candidate",
			TargetDeviceID: p.DeviceID,
			Candidate:      init.Candidate,
			SDPMid:         sdpMid,
			SDPMLineIndex:  mLineIndex,
		}); err != nil {
			p.logger.Warn("failed to send ICE candidate", "error", err)
		}
	})

	p.conn.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		p.logger.Info("peer connection state", "state", state.String())
		if state == webrtc.PeerConnectionStateFailed ||
			state == webrtc.PeerConnectionStateClosed ||
			state == webrtc.PeerConnectionStateDisconnected {
			p.logger.Info("peer connection ended", "state", state.String())
		}
	})
}

// setupDataChannelHandlers sets up handlers on a DataChannel.
func (p *Peer) setupDataChannelHandlers(dc *webrtc.DataChannel) {
	dc.OnOpen(func() {
		p.logger.Info("DataChannel opened", "label", dc.Label())
	})

	dc.OnClose(func() {
		p.logger.Info("DataChannel closed", "label", dc.Label())
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		decoded, err := protocol.Decode(msg.Data)
		if err != nil {
			p.logger.Debug("failed to decode DataChannel message", "error", err)
			return
		}

		if p.handler != nil {
			p.handler(p.DeviceID, decoded)
		}
	})
}

// SendMessage encodes and sends a protocol message over the DataChannel.
func (p *Peer) SendMessage(msg protocol.Message) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return fmt.Errorf("peer connection closed")
	}

	if p.dc == nil {
		return fmt.Errorf("data channel not established")
	}

	data, err := protocol.Encode(msg)
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}

	return p.dc.Send(data)
}

// Close cleanly shuts down the peer connection.
func (p *Peer) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true

	if p.dc != nil {
		p.dc.Close()
	}
	if p.conn != nil {
		p.conn.Close()
	}
}

// --- Helpers ---

func boolPtr(b bool) *bool {
	return &b
}

