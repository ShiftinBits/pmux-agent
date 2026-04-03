package webrtc

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
)

// DataChannelLabel is the name of the WebRTC DataChannel used for terminal protocol.
const DataChannelLabel = "terminal"

// bufferedAmountLowThreshold is the byte threshold at which the DataChannel
// fires the OnBufferedAmountLow callback, enabling backpressure-aware sending.
const bufferedAmountLowThreshold = 4096

// maxBufferedAmount is the byte threshold above which SendRaw/SendMessage
// block waiting for the buffer to drain. 512KB is generous for terminal data
// (typically kilobytes) while preventing unbounded growth.
const maxBufferedAmount = 512 * 1024

// sendReadyTimeout is the maximum time to wait for the DataChannel buffer
// to drain before returning an error. Prevents permanent deadlock if the
// connection is lost while waiting.
const sendReadyTimeout = 5 * time.Second

// pcDisconnectedTimeout is how long to wait after a PeerConnection enters
// the "disconnected" state before attempting an ICE restart. This grace period
// allows transient network interruptions to recover without intervention.
const pcDisconnectedTimeout = 10 * time.Second

// turnCacheTTL is how long TURN credentials are cached before re-fetching.
// TURN credentials typically have a 24h TTL, so 10 minutes is conservative.
const turnCacheTTL = 10 * time.Minute

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
	logger     *slog.Logger
	signaling  MessageSender
	serverURL  string
	jwt        func() string // returns current JWT
	handler    ProtocolHandler
	hmacSecret string

	// API is the Pion WebRTC API used to create peer connections.
	// If nil, the default API is used. Set this for testing with custom settings.
	API *webrtc.API

	// MaxPeers is the maximum number of simultaneous peer connections allowed.
	// Defaults to 1 (single-pairing mode). Set after construction to override.
	MaxPeers int

	// allowedDeviceID is the single paired mobile device ID.
	// When set, only this device is allowed to connect; others are rejected.
	// Access via SetAllowedDeviceID/getAllowedDeviceID for thread safety.
	allowedDeviceID string

	// OnPeerDisconnect is called when a peer connection enters a terminal state
	// (Failed or Closed). Set by agent.go to point at Handler.PeerDisconnected,
	// which triggers bridge teardown and pane size restore.
	OnPeerDisconnect func(deviceID string)

	mu               sync.Mutex
	peers            map[string]*Peer          // keyed by mobile device ID
	disconnectTimers map[string]*time.Timer    // grace timers for disconnected peers
	disconnectTimes  map[string]time.Time      // wall-clock time of disconnect (for sleep detection)
	cleanupWg        sync.WaitGroup            // tracks background cleanup goroutines
	closed           bool                       // true after CloseAll() returns
	turnCache        []webrtc.ICEServer        // cached TURN credentials
	turnCacheTime    time.Time                 // when turnCache was last populated
}

// Peer represents a single WebRTC peer connection to a mobile device.
type Peer struct {
	DeviceID     string
	conn         *webrtc.PeerConnection
	dc           *webrtc.DataChannel
	logger       *slog.Logger
	signaling    MessageSender
	handler      ProtocolHandler
	stateHandler func(peer *Peer, state webrtc.PeerConnectionState)
	mu             sync.Mutex
	closed         bool
	sendReady      chan struct{} // signaled by OnBufferedAmountLow when buffer drains
	done           chan struct{} // closed by Close() to unblock waitForSendReady
	remoteDescSet  bool                      // true after SetRemoteDescription succeeds
	iceCandidates  []webrtc.ICECandidateInit // buffered candidates received before remote desc
}

// SetAllowedDeviceID updates the allowed device ID under the mutex.
// Safe to call from any goroutine (e.g., SIGUSR2 handler).
func (pm *PeerManager) SetAllowedDeviceID(id string) {
	pm.mu.Lock()
	pm.allowedDeviceID = id
	pm.mu.Unlock()
}

// getAllowedDeviceID returns the allowed device ID under the mutex.
func (pm *PeerManager) getAllowedDeviceID() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.allowedDeviceID
}

// AllowedDeviceID returns the allowed device ID. Thread-safe.
func (pm *PeerManager) AllowedDeviceID() string {
	return pm.getAllowedDeviceID()
}

// NewPeerManager creates a manager for WebRTC peer connections.
func NewPeerManager(logger *slog.Logger, signaling MessageSender, serverURL string, jwtFn func() string, handler ProtocolHandler, hmacSecret string) *PeerManager {
	return &PeerManager{
		logger:           logger,
		signaling:        signaling,
		serverURL:        strings.TrimRight(serverURL, "/"),
		jwt:              jwtFn,
		handler:          handler,
		hmacSecret:       hmacSecret,
		MaxPeers:         1,
		peers:            make(map[string]*Peer),
		disconnectTimers: make(map[string]*time.Timer),
		disconnectTimes:  make(map[string]time.Time),
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
	default:
		pm.logger.Debug("unhandled signaling message type", "type", msg.Type)
	}
}

// ClosePeer closes a specific peer connection.
func (pm *PeerManager) ClosePeer(deviceID string) {
	pm.mu.Lock()
	peer, ok := pm.peers[deviceID]
	if ok {
		delete(pm.peers, deviceID)
	}
	// Cancel any pending disconnect timer for this peer.
	if timer, hasTimer := pm.disconnectTimers[deviceID]; hasTimer {
		timer.Stop()
		delete(pm.disconnectTimers, deviceID)
	}
	delete(pm.disconnectTimes, deviceID)
	peerCount := len(pm.peers)
	pm.mu.Unlock()

	if ok {
		closeStart := time.Now()
		pcState := peer.conn.ConnectionState().String()
		peer.Close()
		pm.logger.Info("peer disconnected",
			"mobile", deviceID,
			"peerCount", peerCount,
			"pcState", pcState,
			"closeElapsed", time.Since(closeStart).Round(time.Millisecond),
			"goroutines", runtime.NumGoroutine(),
		)
	}
}

// CloseAll closes all peer connections and waits for background cleanup
// goroutines (from state change handlers) to finish.
func (pm *PeerManager) CloseAll() {
	pm.mu.Lock()
	pm.closed = true
	peers := make([]*Peer, 0, len(pm.peers))
	for _, p := range pm.peers {
		peers = append(peers, p)
	}
	closedCount := len(peers)
	pm.peers = make(map[string]*Peer)

	// Cancel all pending disconnect timers.
	for deviceID, timer := range pm.disconnectTimers {
		timer.Stop()
		delete(pm.disconnectTimers, deviceID)
	}
	pm.disconnectTimes = make(map[string]time.Time)
	pm.mu.Unlock()

	for _, p := range peers {
		p.Close()
	}

	// Wait for any in-flight cleanup goroutines spawned by handlePeerStateChange
	// or attemptICERestart to finish before returning.
	pm.cleanupWg.Wait()

	if closedCount > 0 {
		pm.logger.Info("all peers closed",
			"closedCount", closedCount,
			"goroutines", runtime.NumGoroutine(),
		)
	}
}

// scheduleCleanup spawns a tracked goroutine that notifies the disconnect
// handler and closes the peer. Safe to call while pm.mu is held because
// ClosePeer runs asynchronously in the spawned goroutine.
// Caller must hold pm.mu.
func (pm *PeerManager) scheduleCleanup(deviceID string) {
	if pm.closed {
		return
	}
	pm.cleanupWg.Add(1)
	go func() {
		defer pm.cleanupWg.Done()
		if pm.OnPeerDisconnect != nil {
			pm.OnPeerDisconnect(deviceID)
		}
		pm.ClosePeer(deviceID)
	}()
}

// PeerCount returns the number of active peer connections.
func (pm *PeerManager) PeerCount() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return len(pm.peers)
}

// PeerStates returns a map of device ID to PeerConnection state string
// for all tracked peers. Used by ConnectionCleaner as a safety net to detect
// peers in failed/closed state that weren't cleaned up by state handlers.
func (pm *PeerManager) PeerStates() map[string]string {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	states := make(map[string]string, len(pm.peers))
	for deviceID, peer := range pm.peers {
		states[deviceID] = peer.conn.ConnectionState().String()
	}
	return states
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
	requestStart := time.Now()
	pm.logger.Info("connect_request received", "mobile", mobileDeviceID)

	// Validate device is the paired device
	allowedID := pm.getAllowedDeviceID()
	if allowedID != "" && mobileDeviceID != allowedID {
		pm.logger.Warn("connection rejected: device not paired",
			"mobile", mobileDeviceID, "expected", allowedID)
		if err := pm.signaling.Send(SignalingMessage{
			Type:           "connection_rejected",
			Reason:         "not_paired",
			TargetDeviceID: mobileDeviceID,
		}); err != nil {
			pm.logger.Warn("failed to send rejection", "error", err)
		}
		return
	}

	// Check connection limit (don't count the requesting device — they may be reconnecting)
	pm.mu.Lock()
	currentCount := len(pm.peers)
	oldPeerForLog, isReconnect := pm.peers[mobileDeviceID]
	pm.mu.Unlock()

	if isReconnect {
		pm.logger.Info("reconnect detected, will replace existing peer",
			"mobile", mobileDeviceID, "oldPcState", oldPeerForLog.conn.ConnectionState().String())
	}

	if !isReconnect && currentCount >= pm.MaxPeers {
		pm.logger.Warn("max peer connections reached", "max", pm.MaxPeers, "mobile", mobileDeviceID)
		if err := pm.signaling.Send(SignalingMessage{
			Type:           "connection_rejected",
			Reason:         "already_connected",
			TargetDeviceID: mobileDeviceID,
		}); err != nil {
			pm.logger.Warn("failed to send rejection to mobile", "error", err, "mobile", mobileDeviceID)
		}
		return
	}

	// Close existing peer connection if any (re-connect scenario).
	// Remove from the map synchronously so the new peer can be added, but
	// close the old PeerConnection in the background. PeerConnection.Close()
	// can block for seconds waiting for DTLS/ICE shutdown with an unreachable
	// peer, which would freeze the signaling readLoop and prevent processing
	// subsequent messages (including the mobile's reconnection attempts).
	pm.mu.Lock()
	oldPeer, hadOld := pm.peers[mobileDeviceID]
	if hadOld {
		delete(pm.peers, mobileDeviceID)
	}
	if timer, hasTimer := pm.disconnectTimers[mobileDeviceID]; hasTimer {
		timer.Stop()
		delete(pm.disconnectTimers, mobileDeviceID)
	}
	delete(pm.disconnectTimes, mobileDeviceID)
	pm.mu.Unlock()

	if hadOld {
		oldState := oldPeer.conn.ConnectionState().String()
		pm.logger.Info("closing old peer for reconnect (async)",
			"mobile", mobileDeviceID, "oldPcState", oldState)
		pm.cleanupWg.Add(1)
		go func() {
			defer pm.cleanupWg.Done()
			start := time.Now()
			oldPeer.Close()
			pm.logger.Info("old peer closed",
				"mobile", mobileDeviceID, "elapsed", time.Since(start).Round(time.Millisecond))
		}()
	}

	// Fetch TURN credentials (skipped when custom API is set, e.g. in tests)
	//
	// Security: RTCConfiguration uses default settings which enforce DTLS encryption.
	// Pion WebRTC requires DTLS by default on all peer connections — there is no
	// unencrypted fallback. Do NOT set config fields that would weaken or disable
	// DTLS (e.g., do not set InsecureSkipVerify or disable certificate verification).
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

		// Log ICE server configuration for diagnostics
		for i, srv := range iceServers {
			pm.logger.Info("ICE server configured", "index", i, "urls", srv.URLs, "hasCredentials", srv.Username != "")
		}
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
		DeviceID:     mobileDeviceID,
		conn:         pc,
		logger:       pm.logger.With("peer", mobileDeviceID),
		signaling:    pm.signaling,
		handler:      pm.handler,
		stateHandler: pm.handlePeerStateChange,
		sendReady:    make(chan struct{}, 1),
		done:         make(chan struct{}),
	}

	pm.mu.Lock()
	// Re-check limit under lock to prevent TOCTOU race if HandleSignalingMessage
	// is called concurrently (the early check above is an unlocked fast path).
	if _, replacing := pm.peers[mobileDeviceID]; !replacing && len(pm.peers) >= pm.MaxPeers {
		pm.mu.Unlock()
		pc.Close()
		pm.logger.Warn("max peer connections reached (concurrent)", "max", pm.MaxPeers, "mobile", mobileDeviceID)
		return
	}
	pm.peers[mobileDeviceID] = peer
	peerCount := len(pm.peers)
	pm.mu.Unlock()

	pm.logger.Info("peer connected",
		"mobile", mobileDeviceID,
		"peerCount", peerCount,
		"goroutines", runtime.NumGoroutine(),
	)

	// Set up event handlers
	peer.setupHandlers()

	// Create DataChannel with ordered delivery.
	// Security: ordered=true is required for terminal I/O correctness — out-of-order
	// delivery would corrupt terminal output. This is explicitly set (not relying on
	// the WebRTC default) to make the security property visible and testable.
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

	pm.logger.Info("SDP offer sent", "mobile", mobileDeviceID, "elapsed", time.Since(requestStart).Round(time.Millisecond))
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
		pm.ClosePeer(mobileDeviceID)
		return
	}

	// Mark remote desc as set and drain buffered ICE candidates.
	peer.mu.Lock()
	peer.remoteDescSet = true
	buffered := peer.iceCandidates
	peer.iceCandidates = nil
	peer.mu.Unlock()

	for _, ice := range buffered {
		if err := peer.conn.AddICECandidate(ice); err != nil {
			pm.logger.Warn("failed to add buffered ICE candidate", "error", err, "mobile", mobileDeviceID)
		}
	}

	pm.logger.Info("SDP answer applied", "mobile", mobileDeviceID, "bufferedCandidates", len(buffered))
}

// handleICECandidate adds an ICE candidate from the mobile peer.
func (pm *PeerManager) handleICECandidate(mobileDeviceID string, candidate string, sdpMid string, sdpMLineIndex *int) {
	pm.logger.Debug("ICE candidate received from mobile", "mobile", mobileDeviceID, "candidate", candidate)

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

	peer.mu.Lock()
	if !peer.remoteDescSet {
		peer.iceCandidates = append(peer.iceCandidates, ice)
		peer.mu.Unlock()
		pm.logger.Debug("ICE candidate buffered (remote desc not set)", "mobile", mobileDeviceID)
		return
	}
	peer.mu.Unlock()

	if err := peer.conn.AddICECandidate(ice); err != nil {
		pm.logger.Warn("failed to add ICE candidate", "error", err, "mobile", mobileDeviceID)
	}
}

// fetchTurnCredentials calls the server API to get TURN credentials.
// Results are cached for turnCacheTTL to avoid redundant HTTP requests
// during rapid reconnection cycles.
func (pm *PeerManager) fetchTurnCredentials() ([]webrtc.ICEServer, error) {
	// Return cached credentials if fresh.
	pm.mu.Lock()
	if len(pm.turnCache) > 0 && time.Since(pm.turnCacheTime) < turnCacheTTL {
		cached := pm.turnCache
		pm.mu.Unlock()
		pm.logger.Debug("using cached TURN credentials", "age", time.Since(pm.turnCacheTime).Round(time.Second))
		return cached, nil
	}
	pm.mu.Unlock()

	url := pm.serverURL + "/turn/credentials"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create TURN request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+pm.jwt())
	auth.SignRequest(req, pm.hmacSecret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("TURN credentials request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB max
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

	pm.logger.Info("TURN credentials fetched", "urls", creds.URLs, "hasUsername", creds.Username != "", "hasCredential", creds.Credential != "")

	servers := []webrtc.ICEServer{{
		URLs:       creds.URLs,
		Username:   creds.Username,
		Credential: creds.Credential,
	}}

	// Cache the result.
	pm.mu.Lock()
	pm.turnCache = servers
	pm.turnCacheTime = time.Now()
	pm.mu.Unlock()

	return servers, nil
}

// handlePeerStateChange is the state change callback for managing disconnect
// timers, ICE restarts, and peer cleanup based on PeerConnection state transitions.
// The peer parameter identifies which Peer fired the callback, preventing stale
// callbacks from an old peer (during reconnect) from cleaning up the new peer.
func (pm *PeerManager) handlePeerStateChange(peer *Peer, state webrtc.PeerConnectionState) {
	deviceID := peer.DeviceID
	pm.mu.Lock()
	defer pm.mu.Unlock()

	switch state {
	case webrtc.PeerConnectionStateConnected:
		// Connection recovered — cancel any pending disconnect timer.
		if timer, ok := pm.disconnectTimers[deviceID]; ok {
			timer.Stop()
			delete(pm.disconnectTimers, deviceID)
			delete(pm.disconnectTimes, deviceID)
			pm.logger.Info("disconnect timer cancelled (connection recovered)", "mobile", deviceID)
		}

	case webrtc.PeerConnectionStateDisconnected:
		// Start a grace timer. If the connection doesn't recover within
		// pcDisconnectedTimeout, attempt an ICE restart.
		if _, ok := pm.disconnectTimers[deviceID]; ok {
			// Timer already running — don't restart it.
			return
		}
		pm.logger.Info("peer disconnected, starting grace timer",
			"mobile", deviceID, "timeout", pcDisconnectedTimeout)
		pm.disconnectTimes[deviceID] = time.Now()
		pm.disconnectTimers[deviceID] = time.AfterFunc(pcDisconnectedTimeout, func() {
			pm.onDisconnectTimerFired(deviceID)
		})

	case webrtc.PeerConnectionStateFailed:
		// Connection unrecoverable — cancel timer, notify handler, and close.
		if timer, ok := pm.disconnectTimers[deviceID]; ok {
			timer.Stop()
			delete(pm.disconnectTimers, deviceID)
		}
		delete(pm.disconnectTimes, deviceID)
		// Only cleanup if the tracked peer is the same one that fired.
		// During reconnect, a stale callback from the old peer may fire after
		// a new peer is stored under the same device ID.
		if tracked, ok := pm.peers[deviceID]; ok && tracked == peer {
			pm.logger.Info("peer connection failed, closing peer", "mobile", deviceID)
			pm.scheduleCleanup(deviceID)
		}

	case webrtc.PeerConnectionStateClosed:
		// Peer connection closed — cancel timer and notify handler.
		if timer, ok := pm.disconnectTimers[deviceID]; ok {
			timer.Stop()
			delete(pm.disconnectTimers, deviceID)
		}
		delete(pm.disconnectTimes, deviceID)
		// Only cleanup if the tracked peer is the same one that fired.
		// During reconnect, a stale callback from the old peer may fire after
		// a new peer is stored under the same device ID.
		if tracked, ok := pm.peers[deviceID]; ok && tracked == peer {
			pm.scheduleCleanup(deviceID)
		}
	}
}

// onDisconnectTimerFired is called when the disconnect grace timer expires.
// It checks whether the peer is still disconnected and attempts an ICE restart.
// Uses wall-clock validation to detect timers that fired early after system sleep.
func (pm *PeerManager) onDisconnectTimerFired(deviceID string) {
	pm.mu.Lock()
	delete(pm.disconnectTimers, deviceID)
	disconnectTime, hasTime := pm.disconnectTimes[deviceID]
	delete(pm.disconnectTimes, deviceID)
	peer, ok := pm.peers[deviceID]
	pm.mu.Unlock()

	if !ok {
		return
	}

	// Only attempt ICE restart if the peer is still in the disconnected state.
	if peer.conn.ConnectionState() != webrtc.PeerConnectionStateDisconnected {
		pm.logger.Debug("disconnect timer fired but peer recovered", "mobile", deviceID)
		return
	}

	// After system sleep, the monotonic timer fires immediately but actual
	// disconnect may have been brief. Re-schedule if wall-clock time is insufficient.
	elapsed := time.Since(disconnectTime)
	if hasTime && elapsed < pcDisconnectedTimeout/2 {
		pm.logger.Debug("disconnect timer fired early (system sleep?), rescheduling",
			"mobile", deviceID, "elapsed", elapsed)
		remaining := pcDisconnectedTimeout - elapsed
		pm.mu.Lock()
		pm.disconnectTimes[deviceID] = disconnectTime
		pm.disconnectTimers[deviceID] = time.AfterFunc(remaining, func() {
			pm.onDisconnectTimerFired(deviceID)
		})
		pm.mu.Unlock()
		return
	}

	pm.logger.Info("disconnect timer expired, attempting ICE restart", "mobile", deviceID)
	pm.attemptICERestart(deviceID)
}

// attemptICERestart creates a new SDP offer with the ICE restart flag and sends
// it to the mobile via signaling. If any step fails, the peer is closed and the
// mobile will need to perform a full reconnect.
func (pm *PeerManager) attemptICERestart(deviceID string) {
	pm.mu.Lock()
	peer, ok := pm.peers[deviceID]
	pm.mu.Unlock()

	if !ok {
		return
	}

	offer, err := peer.conn.CreateOffer(&webrtc.OfferOptions{ICERestart: true})
	if err != nil {
		pm.logger.Error("ICE restart: failed to create offer", "error", err, "mobile", deviceID)
		pm.mu.Lock()
		pm.scheduleCleanup(deviceID)
		pm.mu.Unlock()
		return
	}

	if err := peer.conn.SetLocalDescription(offer); err != nil {
		pm.logger.Error("ICE restart: failed to set local description", "error", err, "mobile", deviceID)
		pm.mu.Lock()
		pm.scheduleCleanup(deviceID)
		pm.mu.Unlock()
		return
	}

	peer.mu.Lock()
	peer.remoteDescSet = false
	peer.iceCandidates = nil
	peer.mu.Unlock()

	if err := pm.signaling.Send(SignalingMessage{
		Type:           "sdp_offer",
		TargetDeviceID: deviceID,
		SDP:            offer.SDP,
	}); err != nil {
		pm.logger.Error("ICE restart: failed to send SDP offer", "error", err, "mobile", deviceID)
		pm.mu.Lock()
		pm.scheduleCleanup(deviceID)
		pm.mu.Unlock()
		return
	}

	pm.logger.Info("ICE restart offer sent", "mobile", deviceID)
}

// --- Peer methods ---
//
// Security: DataChannel messages contain only terminal protocol data (session lists,
// terminal I/O, pane attach/detach, ping/pong). No private keys, JWTs, or other
// authentication credentials are ever transmitted over the DataChannel. Authentication
// is handled entirely through the signaling server over TLS. See protocol/messages.go
// for the complete set of DataChannel message types.

// setupHandlers configures ICE and connection state handlers on the peer connection.
func (p *Peer) setupHandlers() {
	p.conn.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			p.logger.Debug("ICE gathering complete")
			return
		}
		p.logger.Debug("ICE candidate gathered", "type", c.Typ.String(), "address", c.Address, "port", c.Port, "protocol", c.Protocol.String())
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

		if state == webrtc.PeerConnectionStateConnected {
			// Log DTLS transport security info on successful connection.
			// This confirms encryption is active and records the cipher suite
			// for security auditing and potential future fingerprint pinning.
			p.logDTLSInfo()
		}

		if state == webrtc.PeerConnectionStateFailed ||
			state == webrtc.PeerConnectionStateClosed ||
			state == webrtc.PeerConnectionStateDisconnected {
			p.logger.Info("peer connection ended", "state", state.String())
		}

		// Notify the PeerManager of state changes for disconnect timer
		// management and ICE restart logic.
		if p.stateHandler != nil {
			p.stateHandler(p, state)
		}
	})
}

// setupDataChannelHandlers sets up handlers on a DataChannel.
func (p *Peer) setupDataChannelHandlers(dc *webrtc.DataChannel) {
	// Set the buffered amount low threshold for backpressure awareness.
	// When the buffered amount drops below this threshold, the
	// OnBufferedAmountLow callback fires, enabling flow control.
	dc.SetBufferedAmountLowThreshold(bufferedAmountLowThreshold)

	// Signal the send goroutine that the buffer has drained and it can resume
	// sending. Non-blocking send avoids goroutine leak if nobody is waiting.
	// sendReady is never closed, so this cannot panic.
	dc.OnBufferedAmountLow(func() {
		select {
		case p.sendReady <- struct{}{}:
		default:
		}
	})

	dc.OnOpen(func() {
		p.logger.Info("DataChannel opened", "label", dc.Label())
	})

	dc.OnClose(func() {
		p.logger.Info("DataChannel closed", "label", dc.Label())
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		defer func() {
			if r := recover(); r != nil {
				p.logger.Error("panic in DataChannel message handler",
					"recover", r, "device", p.DeviceID,
					"stack", string(debug.Stack()))
			}
		}()

		decoded, err := protocol.Decode(msg.Data)
		if err != nil {
			p.logger.Debug("failed to decode DataChannel message", "error", err)
			return
		}

		// Only accept request-direction messages from mobile.
		if !protocol.IsRequest(decoded) {
			p.logger.Debug("ignoring non-request message from mobile",
				"type", decoded.MessageType(), "device", p.DeviceID)
			return
		}

		if p.handler != nil {
			p.handler(p.DeviceID, decoded)
		}
	})
}

// logDTLSInfo logs DTLS transport stats (cipher suite, state, certificate IDs) when the
// peer connection is established. This confirms that DTLS encryption is active
// and provides audit trail data for the security model.
func (p *Peer) logDTLSInfo() {
	stats := p.conn.GetStats()
	for _, s := range stats {
		transport, ok := s.(webrtc.TransportStats)
		if !ok {
			continue
		}
		p.logger.Info("DTLS transport active",
			"dtlsState", transport.DTLSState,
			"dtlsCipher", transport.DTLSCipher,
			"srtpCipher", transport.SRTPCipher,
			"localCertificateId", transport.LocalCertificateID,
			"remoteCertificateId", transport.RemoteCertificateID,
		)
	}
}

// waitForSendReady blocks if the DataChannel buffer exceeds maxBufferedAmount,
// waiting for the OnBufferedAmountLow callback to signal that sending can resume.
// Returns an error if the timeout expires or the peer is closed (done channel
// is closed by Close()). The dc parameter must be captured under p.mu before
// calling this method (which runs without the lock held).
func (p *Peer) waitForSendReady(dc *webrtc.DataChannel) error {
	// Drain any stale signal from a prior drain cycle to prevent false
	// fast-path returns when the buffer has refilled since the last signal.
	select {
	case <-p.sendReady:
	default:
	}

	if dc.BufferedAmount() <= maxBufferedAmount {
		return nil
	}
	p.logger.Debug("backpressure: waiting for buffer to drain",
		"buffered", dc.BufferedAmount(), "max", maxBufferedAmount)
	select {
	case <-p.sendReady:
		return nil
	case <-p.done:
		return fmt.Errorf("peer connection closed")
	case <-time.After(sendReadyTimeout):
		return fmt.Errorf("send timeout: DataChannel buffer full (%d bytes)", dc.BufferedAmount())
	}
}

// SendRaw sends pre-encoded bytes directly over the DataChannel.
// Blocks if the send buffer is full, waiting for backpressure to clear.
func (p *Peer) SendRaw(data []byte) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return fmt.Errorf("peer connection closed")
	}
	if p.dc == nil {
		p.mu.Unlock()
		return fmt.Errorf("data channel not established")
	}
	dc := p.dc
	p.mu.Unlock()

	// Wait without holding p.mu so Close() can proceed concurrently.
	if err := p.waitForSendReady(dc); err != nil {
		return fmt.Errorf("backpressure: %w", err)
	}
	return dc.Send(data)
}

// SendMessage encodes and sends a protocol message over the DataChannel.
// Blocks if the send buffer is full, waiting for backpressure to clear.
func (p *Peer) SendMessage(msg protocol.Message) error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return fmt.Errorf("peer connection closed")
	}
	if p.dc == nil {
		p.mu.Unlock()
		return fmt.Errorf("data channel not established")
	}
	dc := p.dc
	p.mu.Unlock()

	data, err := protocol.Encode(msg)
	if err != nil {
		return fmt.Errorf("encode message: %w", err)
	}

	// Wait without holding p.mu so Close() can proceed concurrently.
	if err := p.waitForSendReady(dc); err != nil {
		return fmt.Errorf("backpressure: %w", err)
	}
	return dc.Send(data)
}

// Close cleanly shuts down the peer connection. Closing the done channel
// unblocks any goroutine waiting in waitForSendReady so it returns
// immediately instead of waiting for the full sendReadyTimeout.
func (p *Peer) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true
	close(p.done) // unblock any waiting senders immediately

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

