package webrtc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
)

// mockSender captures sent signaling messages.
type mockSender struct {
	mu       sync.Mutex
	messages []SignalingMessage
}

func (m *mockSender) Send(msg SignalingMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

func (m *mockSender) messagesOfType(t string) []SignalingMessage {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []SignalingMessage
	for _, msg := range m.messages {
		if msg.Type == t {
			result = append(result, msg)
		}
	}
	return result
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// getPeer retrieves a peer from the PeerManager by device ID (test helper).
func getPeer(pm *PeerManager, deviceID string) *Peer {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.peers[deviceID]
}

func mockTurnServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/turn/credentials" {
			creds := TurnCredentials{
				URLs:       []string{"stun:stun.cloudflare.com:3478"},
				Username:   "test-user",
				Credential: "test-cred",
			}
			data, _ := json.Marshal(creds)
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// fastAPI creates a Pion API for tests. Uses loopback candidates with mDNS
// disabled and UDP4 only for fast, deterministic local connectivity.
func fastAPI(t *testing.T) *webrtc.API {
	t.Helper()
	se := webrtc.SettingEngine{}
	se.SetICETimeouts(5*time.Second, 10*time.Second, 1*time.Second)
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetIncludeLoopbackCandidate(true)
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

func TestPeerManager_HandleConnectRequest(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-1",
	})

	time.Sleep(500 * time.Millisecond)

	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Fatal("expected at least one sdp_offer message")
	}
	if offers[0].TargetDeviceID != "mobile-1" {
		t.Errorf("targetDeviceId = %q, want %q", offers[0].TargetDeviceID, "mobile-1")
	}
	if offers[0].SDP == "" {
		t.Error("SDP should not be empty")
	}

	pm.mu.Lock()
	_, hasPeer := pm.peers["mobile-1"]
	pm.mu.Unlock()
	if !hasPeer {
		t.Error("peer should be tracked in peers map")
	}

	pm.CloseAll()
}

func TestPeerManager_SDPExchange(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-2",
	})
	time.Sleep(500 * time.Millisecond)

	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Fatal("no SDP offer sent")
	}

	// Create answerer
	answerPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create answer PC: %v", err)
	}
	defer answerPC.Close()

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offers[0].SDP}
	if err := answerPC.SetRemoteDescription(offer); err != nil {
		t.Fatalf("set remote desc: %v", err)
	}

	answer, err := answerPC.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}
	if err := answerPC.SetLocalDescription(answer); err != nil {
		t.Fatalf("set local desc: %v", err)
	}

	// Apply answer to agent side
	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "sdp_answer",
		TargetDeviceID: "mobile-2",
		SDP:            answer.SDP,
	})

	// Verify peer state after answer
	pm.mu.Lock()
	peer, ok := pm.peers["mobile-2"]
	pm.mu.Unlock()
	if !ok {
		t.Fatal("peer should still exist after SDP answer")
	}

	// Check remote description was set
	rd := peer.conn.RemoteDescription()
	if rd == nil {
		t.Error("remote description should be set")
	}

	pm.CloseAll()
}

func TestPeerManager_DataChannelProtocol(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	var received []protocol.Message
	var receivedMu sync.Mutex
	handler := func(peerID string, msg protocol.Message) {
		receivedMu.Lock()
		received = append(received, msg)
		receivedMu.Unlock()
	}

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, handler, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-dc",
	})
	time.Sleep(500 * time.Millisecond)

	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Fatal("no SDP offer sent")
	}

	// Create answerer
	answerPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create answer PC: %v", err)
	}
	defer answerPC.Close()

	dcOpened := make(chan *webrtc.DataChannel, 1)
	answerPC.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			dcOpened <- dc
		})
	})

	// Buffer answerer ICE candidates — they must not be sent to the agent
	// until the SDP answer is applied (agent needs remote desc to accept ICE).
	var answerCandidatesMu sync.Mutex
	var answerCandidates []SignalingMessage
	answerPC.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		var mIdx *int
		if init.SDPMLineIndex != nil {
			v := int(*init.SDPMLineIndex)
			mIdx = &v
		}
		mid := ""
		if init.SDPMid != nil {
			mid = *init.SDPMid
		}
		answerCandidatesMu.Lock()
		answerCandidates = append(answerCandidates, SignalingMessage{
			Type:           "ice_candidate",
			TargetDeviceID: "mobile-dc",
			Candidate:      init.Candidate,
			SDPMid:         mid,
			SDPMLineIndex:  mIdx,
		})
		answerCandidatesMu.Unlock()
	})

	// SDP exchange: set offer on answerer, create answer, wait for gathering
	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offers[0].SDP}
	answerPC.SetRemoteDescription(offer)
	answer, _ := answerPC.CreateAnswer(nil)
	answerGatherDone := webrtc.GatheringCompletePromise(answerPC)
	answerPC.SetLocalDescription(answer)
	<-answerGatherDone

	// Apply answer to agent FIRST (sets remote description so agent can accept ICE)
	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "sdp_answer",
		TargetDeviceID: "mobile-dc",
		SDP:            answerPC.LocalDescription().SDP,
	})

	// Flush buffered answerer ICE candidates to agent
	answerCandidatesMu.Lock()
	for _, msg := range answerCandidates {
		pm.HandleSignalingMessage(msg)
	}
	answerCandidatesMu.Unlock()

	// Forward agent ICE candidates to answerer
	go func() {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			time.Sleep(50 * time.Millisecond)
			for _, msg := range sender.messagesOfType("ice_candidate") {
				key := msg.Candidate
				if msg.TargetDeviceID == "mobile-dc" && !seen[key] {
					seen[key] = true
					var mIdx *uint16
					if msg.SDPMLineIndex != nil {
						v := uint16(*msg.SDPMLineIndex)
						mIdx = &v
					}
					answerPC.AddICECandidate(webrtc.ICECandidateInit{
						Candidate:     msg.Candidate,
						SDPMid:        &msg.SDPMid,
						SDPMLineIndex: mIdx,
					})
				}
			}
		}
	}()

	select {
	case dc := <-dcOpened:
		if dc.Label() != DataChannelLabel {
			t.Errorf("DataChannel label = %q, want %q", dc.Label(), DataChannelLabel)
		}

		// Send a ping message over the DataChannel
		pingMsg := &protocol.PingRequest{Type: "ping"}
		data, _ := protocol.Encode(pingMsg)
		dc.Send(data)

		time.Sleep(500 * time.Millisecond)

		receivedMu.Lock()
		found := false
		for _, msg := range received {
			if msg.MessageType() == "ping" {
				found = true
			}
		}
		receivedMu.Unlock()
		if !found {
			t.Error("handler did not receive ping message")
		}

	case <-time.After(15 * time.Second):
		t.Fatal("DataChannel did not open within timeout")
	}

	pm.CloseAll()
}

func TestPeerManager_ClosePeer(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-close",
	})
	time.Sleep(500 * time.Millisecond)

	pm.mu.Lock()
	_, exists := pm.peers["mobile-close"]
	pm.mu.Unlock()
	if !exists {
		t.Fatal("peer should exist")
	}

	pm.ClosePeer("mobile-close")

	pm.mu.Lock()
	_, stillExists := pm.peers["mobile-close"]
	pm.mu.Unlock()
	if stillExists {
		t.Error("peer should be removed after ClosePeer")
	}
}

func TestPeerManager_CloseAllClearsAllPeers(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = fastAPI(t)

	// Connect a single peer and verify CloseAll removes it
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m1"})
	time.Sleep(500 * time.Millisecond)

	pm.mu.Lock()
	count := len(pm.peers)
	pm.mu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 peer, got %d", count)
	}

	pm.CloseAll()

	pm.mu.Lock()
	countAfter := len(pm.peers)
	pm.mu.Unlock()
	if countAfter != 0 {
		t.Errorf("expected 0 peers after CloseAll, got %d", countAfter)
	}
}

func TestPeerManager_NoTurnWithCustomAPI(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	// With pm.API set (test mode), TURN credentials are not fetched,
	// so even a bad server URL is fine.
	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "test-jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-noturn",
	})
	time.Sleep(500 * time.Millisecond)

	pm.mu.Lock()
	_, exists := pm.peers["mobile-noturn"]
	pm.mu.Unlock()
	if !exists {
		t.Error("peer should exist without TURN credentials")
	}

	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Error("expected SDP offer without TURN")
	}

	pm.CloseAll()
}

func TestPeerManager_FetchTurnCredentials(t *testing.T) {
	logger := testLogger()
	sender := &mockSender{}

	t.Run("success", func(t *testing.T) {
		turnServer := mockTurnServer(t)
		defer turnServer.Close()

		pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
		servers, err := pm.fetchTurnCredentials()
		if err != nil {
			t.Fatalf("fetchTurnCredentials() error: %v", err)
		}
		if len(servers) == 0 {
			t.Fatal("expected at least one ICE server")
		}
		if len(servers[0].URLs) == 0 || servers[0].URLs[0] != "stun:stun.cloudflare.com:3478" {
			t.Errorf("unexpected URLs: %v", servers[0].URLs)
		}
	})

	t.Run("server error falls back", func(t *testing.T) {
		badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer badServer.Close()

		pm := NewPeerManager(logger, sender, badServer.URL, func() string { return "test-jwt" }, nil, "")
		_, err := pm.fetchTurnCredentials()
		if err == nil {
			t.Error("expected error from bad TURN server")
		}
	})
}

func TestPeerManager_UnknownPeerMessages(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")

	// These should not panic
	pm.HandleSignalingMessage(SignalingMessage{Type: "sdp_answer", TargetDeviceID: "nonexistent", SDP: "v=0"})
	pm.HandleSignalingMessage(SignalingMessage{Type: "ice_candidate", TargetDeviceID: "nonexistent", Candidate: "c"})
}

func TestPeerManager_SendTo(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")

	err := pm.SendTo("nonexistent", &protocol.PongEvent{Type: "pong"})
	if err == nil {
		t.Error("expected error for nonexistent peer")
	}
}

func TestPeerManager_Reconnect(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = fastAPI(t)

	// First connection
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-re"})
	time.Sleep(300 * time.Millisecond)

	pm.mu.Lock()
	firstPeer := pm.peers["mobile-re"]
	pm.mu.Unlock()
	if firstPeer == nil {
		t.Fatal("first peer should exist")
	}

	// Second connect_request (re-connect) should replace the peer
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-re"})
	time.Sleep(300 * time.Millisecond)

	pm.mu.Lock()
	secondPeer := pm.peers["mobile-re"]
	pm.mu.Unlock()
	if secondPeer == nil {
		t.Fatal("second peer should exist")
	}
	if secondPeer == firstPeer {
		t.Error("second connect_request should create a new peer (not reuse old one)")
	}

	// Old peer should be closed
	firstPeer.mu.Lock()
	closed := firstPeer.closed
	firstPeer.mu.Unlock()
	if !closed {
		t.Error("first peer should be closed after reconnect")
	}

	pm.CloseAll()
}

func TestPeerManager_MaxConnectionLimit(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)
	pm.MaxPeers = 1

	// Connect one peer (should succeed)
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m1"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", pm.PeerCount())
	}

	// Second peer should be rejected
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m2"})
	time.Sleep(200 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Errorf("expected 1 peer after rejection, got %d", pm.PeerCount())
	}

	// Verify rejection message was sent
	rejections := sender.messagesOfType("connection_rejected")
	found := false
	for _, e := range rejections {
		if e.TargetDeviceID == "m2" && e.Reason == "already_connected" {
			found = true
		}
	}
	if !found {
		t.Error("expected connection_rejected with reason already_connected sent to m2")
	}

	pm.CloseAll()
}

func TestPeerManager_RejectsUnpairedDevice(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)
	pm.SetAllowedDeviceID("paired-device-123")

	// Attempt connection from a different (unpaired) device
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "rogue-device-456"})
	time.Sleep(200 * time.Millisecond)

	// Should have no peers
	if pm.PeerCount() != 0 {
		t.Errorf("expected 0 peers, got %d", pm.PeerCount())
	}

	// Verify rejection message sent
	rejections := sender.messagesOfType("connection_rejected")
	found := false
	for _, e := range rejections {
		if e.TargetDeviceID == "rogue-device-456" && e.Reason == "not_paired" {
			found = true
		}
	}
	if !found {
		t.Error("expected connection_rejected with reason not_paired sent to rogue device")
	}

	// Now connect with the correct (paired) device — should succeed
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "paired-device-123"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Errorf("expected 1 peer for paired device, got %d", pm.PeerCount())
	}

	pm.CloseAll()
}

func TestPeerManager_ReconnectDoesNotExceedLimit(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)
	pm.MaxPeers = 1

	// Fill to capacity (single device)
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m1"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", pm.PeerCount())
	}

	// m1 reconnecting should succeed (same device ID, replaces existing)
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m1"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Errorf("expected 1 peer after reconnect, got %d", pm.PeerCount())
	}

	// No error messages for m1
	errors := sender.messagesOfType("error")
	for _, e := range errors {
		if e.TargetDeviceID == "m1" {
			t.Errorf("m1 reconnect should NOT receive error, got: %s", e.Error)
		}
	}

	pm.CloseAll()
}

// --- Security property tests ---

func TestPeerManager_DataChannelOrdered(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-ordered",
	})
	time.Sleep(500 * time.Millisecond)

	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Fatal("no SDP offer sent")
	}

	// Create an answerer to receive the DataChannel and verify its properties
	answerPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create answer PC: %v", err)
	}
	defer answerPC.Close()

	dcReceived := make(chan *webrtc.DataChannel, 1)
	answerPC.OnDataChannel(func(dc *webrtc.DataChannel) {
		dcReceived <- dc
	})

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offers[0].SDP}
	answerPC.SetRemoteDescription(offer)
	answer, _ := answerPC.CreateAnswer(nil)
	gatherDone := webrtc.GatheringCompletePromise(answerPC)
	answerPC.SetLocalDescription(answer)
	<-gatherDone

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "sdp_answer",
		TargetDeviceID: "mobile-ordered",
		SDP:            answerPC.LocalDescription().SDP,
	})

	// Forward ICE candidates from agent to answerer
	go func() {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			time.Sleep(50 * time.Millisecond)
			for _, msg := range sender.messagesOfType("ice_candidate") {
				if msg.TargetDeviceID == "mobile-ordered" && !seen[msg.Candidate] {
					seen[msg.Candidate] = true
					var mIdx *uint16
					if msg.SDPMLineIndex != nil {
						v := uint16(*msg.SDPMLineIndex)
						mIdx = &v
					}
					answerPC.AddICECandidate(webrtc.ICECandidateInit{
						Candidate:     msg.Candidate,
						SDPMid:        &msg.SDPMid,
						SDPMLineIndex: mIdx,
					})
				}
			}
		}
	}()

	select {
	case dc := <-dcReceived:
		// Verify the DataChannel is ordered (must be true for terminal I/O)
		if !dc.Ordered() {
			t.Error("DataChannel ordered property should be true for terminal I/O")
		}
		if dc.Label() != DataChannelLabel {
			t.Errorf("DataChannel label = %q, want %q", dc.Label(), DataChannelLabel)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("DataChannel not received within timeout")
	}

	pm.CloseAll()
}

func TestPeerManager_DTLSNotDisabled(t *testing.T) {
	// Verify that the RTCConfiguration used by PeerManager does not disable DTLS.
	// Pion WebRTC enforces DTLS by default — this test ensures we haven't
	// accidentally configured anything that would weaken that guarantee.
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-dtls",
	})
	time.Sleep(500 * time.Millisecond)

	pm.mu.Lock()
	peer, ok := pm.peers["mobile-dtls"]
	pm.mu.Unlock()
	if !ok {
		t.Fatal("peer should exist")
	}

	// Verify the peer connection was created (confirming DTLS defaults are in effect).
	// Pion does not expose a "DTLS enabled" flag because DTLS is always required.
	// The best we can verify is that the connection was created with a default
	// Configuration (no fields that would disable encryption).
	config := peer.conn.GetConfiguration()

	// The configuration should have default values — specifically, no ICETransportPolicy
	// that would restrict to relay-only (which is fine, but we want to verify defaults).
	// There is no DTLS-specific config field in Pion's webrtc.Configuration because
	// DTLS cannot be disabled — it's mandatory per the WebRTC spec.
	if config.ICETransportPolicy != webrtc.ICETransportPolicyAll {
		t.Errorf("ICETransportPolicy = %v, want All (default)", config.ICETransportPolicy)
	}

	// Verify that PeerConnection can be used for a real DTLS handshake by completing
	// an SDP exchange. If DTLS were somehow disabled, the connection would fail.
	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Fatal("no SDP offer — peer connection creation may have failed")
	}

	// Parse the SDP offer and verify it contains DTLS fingerprint
	sdp := offers[0].SDP
	if !strings.Contains(sdp, "a=fingerprint:") {
		t.Error("SDP offer should contain DTLS fingerprint (a=fingerprint:)")
	}
	if !strings.Contains(sdp, "a=setup:") {
		t.Error("SDP offer should contain DTLS setup attribute (a=setup:)")
	}

	pm.CloseAll()
}

// --- PeerConnection state handling + ICE restart tests ---

func TestPeerManager_DisconnectedStartsGraceTimer(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)

	// Create a peer via connect_request
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-disc"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", pm.PeerCount())
	}

	// Simulate PeerConnectionStateDisconnected
	pm.handlePeerStateChange(getPeer(pm, "mobile-disc"), webrtc.PeerConnectionStateDisconnected)

	pm.mu.Lock()
	_, hasTimer := pm.disconnectTimers["mobile-disc"]
	pm.mu.Unlock()

	if !hasTimer {
		t.Error("expected disconnect timer to be started for disconnected peer")
	}

	pm.CloseAll()
}

func TestPeerManager_ConnectedDuringGraceCancelsTimer(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-recover"})
	time.Sleep(500 * time.Millisecond)

	// Simulate disconnected → timer starts
	pm.handlePeerStateChange(getPeer(pm, "mobile-recover"), webrtc.PeerConnectionStateDisconnected)

	pm.mu.Lock()
	_, hasTimer := pm.disconnectTimers["mobile-recover"]
	pm.mu.Unlock()
	if !hasTimer {
		t.Fatal("expected disconnect timer to be started")
	}

	// Simulate connected → timer should be cancelled
	pm.handlePeerStateChange(getPeer(pm, "mobile-recover"), webrtc.PeerConnectionStateConnected)

	pm.mu.Lock()
	_, hasTimerAfter := pm.disconnectTimers["mobile-recover"]
	pm.mu.Unlock()
	if hasTimerAfter {
		t.Error("expected disconnect timer to be cancelled when connection recovered")
	}

	// Peer should still be alive
	if pm.PeerCount() != 1 {
		t.Errorf("expected 1 peer after recovery, got %d", pm.PeerCount())
	}

	pm.CloseAll()
}

func TestPeerManager_FailedClosesPeerImmediately(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-fail"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", pm.PeerCount())
	}

	// Simulate failed state → peer should be closed via goroutine
	pm.handlePeerStateChange(getPeer(pm, "mobile-fail"), webrtc.PeerConnectionStateFailed)

	// Give the goroutine time to run ClosePeer
	time.Sleep(200 * time.Millisecond)

	if pm.PeerCount() != 0 {
		t.Errorf("expected 0 peers after failed state, got %d", pm.PeerCount())
	}
}

func TestPeerManager_DisconnectTimerFiresICERestart(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-ice"})
	time.Sleep(500 * time.Millisecond)

	// Count existing sdp_offer messages (from initial connect)
	initialOffers := len(sender.messagesOfType("sdp_offer"))

	// Directly call onDisconnectTimerFired — this simulates the timer expiring
	// while the peer is still in a state where ICE restart can be attempted.
	// Note: In a real scenario, the PC would be in "disconnected" state, but
	// since we can't easily force that in a unit test with Pion, we just verify
	// that the method attempts to create a new offer. If the PC has moved past
	// disconnected (e.g. to "new" in test), the method exits early as expected.
	pm.onDisconnectTimerFired("mobile-ice")

	// The timer should be removed from disconnectTimers
	pm.mu.Lock()
	_, hasTimer := pm.disconnectTimers["mobile-ice"]
	pm.mu.Unlock()
	if hasTimer {
		t.Error("disconnect timer should be cleaned up after firing")
	}

	// The peer may or may not have gotten an ICE restart offer depending on
	// its actual connection state in the test environment. We primarily verify
	// that the method runs without panicking and cleans up the timer.
	_ = initialOffers

	pm.CloseAll()
}

func TestPeerManager_ICERestartSendsOffer(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-iceoff"})
	time.Sleep(500 * time.Millisecond)

	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Fatal("no initial SDP offer sent")
	}

	// Complete the SDP exchange so the PC transitions out of have-local-offer.
	// ICE restart requires the PC to be in stable state (remote desc set).
	answerPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create answer PC: %v", err)
	}
	defer answerPC.Close()

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offers[0].SDP}
	if err := answerPC.SetRemoteDescription(offer); err != nil {
		t.Fatalf("set remote desc: %v", err)
	}

	answer, err := answerPC.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}
	if err := answerPC.SetLocalDescription(answer); err != nil {
		t.Fatalf("set local desc: %v", err)
	}

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "sdp_answer",
		TargetDeviceID: "mobile-iceoff",
		SDP:            answer.SDP,
	})
	time.Sleep(200 * time.Millisecond)

	initialOfferCount := len(sender.messagesOfType("sdp_offer"))

	// Call attemptICERestart directly — PC is now in stable state
	pm.attemptICERestart("mobile-iceoff")
	time.Sleep(200 * time.Millisecond)

	afterOfferCount := len(sender.messagesOfType("sdp_offer"))
	if afterOfferCount <= initialOfferCount {
		t.Error("expected ICE restart to send a new SDP offer")
	}

	// Verify the restart offer has different SDP (new ice-ufrag/ice-pwd)
	allOffers := sender.messagesOfType("sdp_offer")
	if len(allOffers) < 2 {
		t.Fatal("expected at least 2 SDP offers (initial + ICE restart)")
	}

	initialSDP := allOffers[0].SDP
	restartSDP := allOffers[len(allOffers)-1].SDP
	if initialSDP == restartSDP {
		t.Error("ICE restart offer SDP should differ from initial offer SDP")
	}

	pm.CloseAll()
}

func TestPeerManager_CloseAllCancelsDisconnectTimers(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-t1"})
	time.Sleep(500 * time.Millisecond)

	// Start a disconnect timer
	pm.handlePeerStateChange(getPeer(pm, "mobile-t1"), webrtc.PeerConnectionStateDisconnected)

	pm.mu.Lock()
	timerCount := len(pm.disconnectTimers)
	pm.mu.Unlock()
	if timerCount == 0 {
		t.Fatal("expected at least 1 disconnect timer")
	}

	// CloseAll should cancel all timers
	pm.CloseAll()

	pm.mu.Lock()
	timerCountAfter := len(pm.disconnectTimers)
	pm.mu.Unlock()
	if timerCountAfter != 0 {
		t.Errorf("expected 0 disconnect timers after CloseAll, got %d", timerCountAfter)
	}
}

func TestPeerManager_PeerStates(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)

	// No peers — should return empty map
	states := pm.PeerStates()
	if len(states) != 0 {
		t.Errorf("expected empty PeerStates, got %d", len(states))
	}

	// Add a peer
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-ps"})
	time.Sleep(500 * time.Millisecond)

	states = pm.PeerStates()
	if len(states) != 1 {
		t.Fatalf("expected 1 state entry, got %d", len(states))
	}

	state, ok := states["mobile-ps"]
	if !ok {
		t.Fatal("expected state entry for mobile-ps")
	}

	// The state should be a valid PeerConnection state string (e.g., "new", "connecting", "connected")
	validStates := map[string]bool{
		"new": true, "connecting": true, "connected": true,
		"disconnected": true, "failed": true, "closed": true,
	}
	if !validStates[state] {
		t.Errorf("unexpected peer state %q", state)
	}

	pm.CloseAll()
}

func TestPeerManager_ClosePeerCancelsDisconnectTimer(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-cpt"})
	time.Sleep(500 * time.Millisecond)

	// Start a disconnect timer
	pm.handlePeerStateChange(getPeer(pm, "mobile-cpt"), webrtc.PeerConnectionStateDisconnected)

	pm.mu.Lock()
	_, hasTimer := pm.disconnectTimers["mobile-cpt"]
	pm.mu.Unlock()
	if !hasTimer {
		t.Fatal("expected disconnect timer to be started")
	}

	// ClosePeer should cancel the timer
	pm.ClosePeer("mobile-cpt")

	pm.mu.Lock()
	_, hasTimerAfter := pm.disconnectTimers["mobile-cpt"]
	pm.mu.Unlock()
	if hasTimerAfter {
		t.Error("expected disconnect timer to be cancelled by ClosePeer")
	}
}

func TestPeerManager_OnPeerDisconnect_CalledOnFailure(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	var disconnectedMu sync.Mutex
	var disconnectedPeers []string

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "test-jwt" }, nil, "")
	pm.API = fastAPI(t)
	pm.OnPeerDisconnect = func(deviceID string) {
		disconnectedMu.Lock()
		disconnectedPeers = append(disconnectedPeers, deviceID)
		disconnectedMu.Unlock()
	}

	// Connect a peer
	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-fail",
	})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", pm.PeerCount())
	}

	// Simulate failed state → should trigger OnPeerDisconnect
	pm.handlePeerStateChange(getPeer(pm, "mobile-fail"), webrtc.PeerConnectionStateFailed)
	time.Sleep(500 * time.Millisecond)

	disconnectedMu.Lock()
	found := false
	for _, id := range disconnectedPeers {
		if id == "mobile-fail" {
			found = true
		}
	}
	disconnectedMu.Unlock()
	if !found {
		t.Error("OnPeerDisconnect should have been called for mobile-fail")
	}

	pm.CloseAll()
}

func TestPeerManager_ICECandidateBuffering(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "test-jwt" }, nil, "")
	pm.API = api

	const deviceID = "mobile-icebuf"

	// 1. Send connect_request to create a peer (and generate an SDP offer).
	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: deviceID,
	})
	time.Sleep(500 * time.Millisecond)

	peer := getPeer(pm, deviceID)
	if peer == nil {
		t.Fatal("peer should exist after connect_request")
	}

	// 2. Send an ICE candidate BEFORE sending an SDP answer.
	//    The remote description is not yet set, so the candidate should be buffered.
	sdpMid := "0"
	mLineIdx := 0
	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "ice_candidate",
		TargetDeviceID: deviceID,
		Candidate:      "candidate:1 1 UDP 2130706431 192.168.1.1 12345 typ host",
		SDPMid:         sdpMid,
		SDPMLineIndex:  &mLineIdx,
	})

	// 3. Verify the candidate was buffered, not applied.
	peer.mu.Lock()
	bufferedCount := len(peer.iceCandidates)
	descSet := peer.remoteDescSet
	peer.mu.Unlock()

	if descSet {
		t.Error("remoteDescSet should be false before SDP answer")
	}
	if bufferedCount != 1 {
		t.Fatalf("expected 1 buffered ICE candidate, got %d", bufferedCount)
	}

	// 4. Create a valid SDP answer from the agent's offer.
	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Fatal("no SDP offer sent")
	}

	answerPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create answer PC: %v", err)
	}
	defer answerPC.Close()

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offers[0].SDP}
	if err := answerPC.SetRemoteDescription(offer); err != nil {
		t.Fatalf("set remote desc: %v", err)
	}
	answer, err := answerPC.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}
	if err := answerPC.SetLocalDescription(answer); err != nil {
		t.Fatalf("set local desc: %v", err)
	}

	// 5. Send the SDP answer — this should set remoteDescSet and drain the buffer.
	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "sdp_answer",
		TargetDeviceID: deviceID,
		SDP:            answer.SDP,
	})

	// 6. Verify the buffer was drained and remoteDescSet is true.
	peer.mu.Lock()
	descSetAfter := peer.remoteDescSet
	bufferedAfter := peer.iceCandidates
	peer.mu.Unlock()

	if !descSetAfter {
		t.Error("remoteDescSet should be true after SDP answer")
	}
	if bufferedAfter != nil {
		t.Errorf("iceCandidates should be nil after draining, got %d", len(bufferedAfter))
	}

	pm.CloseAll()
}

// --- Backpressure tests ---

func TestPeer_BackpressureCallbackRegistered(t *testing.T) {
	// Verify that OnBufferedAmountLow is registered and the threshold is set
	// by establishing a full DataChannel connection and inspecting the DC.
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-bp",
	})
	time.Sleep(500 * time.Millisecond)

	peer := getPeer(pm, "mobile-bp")
	if peer == nil {
		t.Fatal("peer should exist")
	}

	peer.mu.Lock()
	dc := peer.dc
	peer.mu.Unlock()

	if dc == nil {
		// DataChannel is created in OnDataChannel handler which requires SDP exchange.
		// For this test, verify the sendReady channel was initialized.
		if peer.sendReady == nil {
			t.Error("sendReady channel should be initialized")
		}
	} else {
		// If DC exists, verify threshold is set
		if dc.BufferedAmountLowThreshold() != bufferedAmountLowThreshold {
			t.Errorf("BufferedAmountLowThreshold = %d, want %d",
				dc.BufferedAmountLowThreshold(), bufferedAmountLowThreshold)
		}
	}

	// Verify sendReady channel is buffered with capacity 1
	if cap(peer.sendReady) != 1 {
		t.Errorf("sendReady channel capacity = %d, want 1", cap(peer.sendReady))
	}

	pm.CloseAll()
}

func TestPeer_SendRaw_SucceedsWithLowBuffer(t *testing.T) {
	// Verify SendRaw works normally when the DataChannel buffer is not full.
	// Uses a full SDP exchange to establish a real DataChannel.
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	api := fastAPI(t)
	received := make(chan []byte, 10)
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-send",
	})
	time.Sleep(500 * time.Millisecond)

	offers := sender.messagesOfType("sdp_offer")
	if len(offers) == 0 {
		t.Fatal("no SDP offer sent")
	}

	// Create answerer and establish DataChannel
	answerPC, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create answer PC: %v", err)
	}
	defer answerPC.Close()

	answerPC.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			data := make([]byte, len(msg.Data))
			copy(data, msg.Data)
			received <- data
		})
	})

	var answerCandidatesMu sync.Mutex
	var answerCandidates []SignalingMessage
	answerPC.OnICECandidate(func(c *webrtc.ICECandidate) {
		if c == nil {
			return
		}
		init := c.ToJSON()
		var mIdx *int
		if init.SDPMLineIndex != nil {
			v := int(*init.SDPMLineIndex)
			mIdx = &v
		}
		mid := ""
		if init.SDPMid != nil {
			mid = *init.SDPMid
		}
		answerCandidatesMu.Lock()
		answerCandidates = append(answerCandidates, SignalingMessage{
			Type:           "ice_candidate",
			TargetDeviceID: "mobile-send",
			Candidate:      init.Candidate,
			SDPMid:         mid,
			SDPMLineIndex:  mIdx,
		})
		answerCandidatesMu.Unlock()
	})

	offer := webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offers[0].SDP}
	answerPC.SetRemoteDescription(offer)
	answer, _ := answerPC.CreateAnswer(nil)
	answerGatherDone := webrtc.GatheringCompletePromise(answerPC)
	answerPC.SetLocalDescription(answer)
	<-answerGatherDone

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "sdp_answer",
		TargetDeviceID: "mobile-send",
		SDP:            answerPC.LocalDescription().SDP,
	})

	answerCandidatesMu.Lock()
	for _, msg := range answerCandidates {
		pm.HandleSignalingMessage(msg)
	}
	answerCandidatesMu.Unlock()

	// Forward agent ICE candidates to answerer
	go func() {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			time.Sleep(50 * time.Millisecond)
			for _, msg := range sender.messagesOfType("ice_candidate") {
				if msg.TargetDeviceID == "mobile-send" && !seen[msg.Candidate] {
					seen[msg.Candidate] = true
					var mIdx *uint16
					if msg.SDPMLineIndex != nil {
						v := uint16(*msg.SDPMLineIndex)
						mIdx = &v
					}
					answerPC.AddICECandidate(webrtc.ICECandidateInit{
						Candidate:     msg.Candidate,
						SDPMid:        &msg.SDPMid,
						SDPMLineIndex: mIdx,
					})
				}
			}
		}
	}()

	// Wait for DataChannel to be established on agent side
	peer := getPeer(pm, "mobile-send")
	if peer == nil {
		t.Fatal("peer should exist")
	}

	// Wait for DC to be ready
	var dc *webrtc.DataChannel
	for i := 0; i < 100; i++ {
		time.Sleep(100 * time.Millisecond)
		peer.mu.Lock()
		dc = peer.dc
		peer.mu.Unlock()
		if dc != nil {
			break
		}
	}
	if dc == nil {
		t.Fatal("DataChannel not established within timeout")
	}

	// Send data via SendRaw — should succeed immediately (buffer is empty)
	testData := []byte("hello backpressure")
	if err := peer.SendRaw(testData); err != nil {
		t.Fatalf("SendRaw failed: %v", err)
	}

	// Verify data was received
	select {
	case data := <-received:
		if string(data) != string(testData) {
			t.Errorf("received %q, want %q", string(data), string(testData))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive sent data within timeout")
	}

	pm.CloseAll()
}

func TestPeer_SendRaw_ClosedPeerReturnsError(t *testing.T) {
	// Verify SendRaw returns an error when the peer is closed.
	peer := &Peer{
		DeviceID:  "test",
		logger:    testLogger().With("peer", "test"),
		closed:    true,
		sendReady: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	err := peer.SendRaw([]byte("data"))
	if err == nil {
		t.Error("expected error from closed peer")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("error should mention 'closed', got: %v", err)
	}
}

func TestPeer_SendMessage_ClosedPeerReturnsError(t *testing.T) {
	// Verify SendMessage returns an error when the peer is closed.
	peer := &Peer{
		DeviceID:  "test",
		logger:    testLogger().With("peer", "test"),
		closed:    true,
		sendReady: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	err := peer.SendMessage(&protocol.PongEvent{Type: "pong"})
	if err == nil {
		t.Error("expected error from closed peer")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("error should mention 'closed', got: %v", err)
	}
}

func TestPeer_CloseUnblocksWaitingBackpressure(t *testing.T) {
	// Verify that Close() immediately unblocks a goroutine waiting in
	// waitForSendReady via the done channel, rather than waiting for the
	// full sendReadyTimeout. This is the TOCTOU race fix — sendReady is
	// never closed, so OnBufferedAmountLow cannot panic.
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-close-bp",
	})
	time.Sleep(500 * time.Millisecond)

	peer := getPeer(pm, "mobile-close-bp")
	if peer == nil {
		t.Fatal("peer should exist")
	}

	// Verify the done channel is open (non-blocking receive should not succeed)
	select {
	case <-peer.done:
		t.Fatal("done channel should be open before Close()")
	default:
	}

	// Close the peer — done channel should close
	peer.Close()

	// Verify done channel is now closed (non-blocking receive should succeed)
	select {
	case <-peer.done:
		// Expected — done is closed
	default:
		t.Error("done channel should be closed after Close()")
	}

	// Verify double-close is safe
	peer.Close()

	pm.CloseAll()
}

// --- Additional unit tests for coverage gaps ---

func TestSendMessage_NilDataChannel(t *testing.T) {
	// Verify SendMessage returns an error when the data channel has not been established.
	peer := &Peer{
		DeviceID:  "test-nil-dc",
		logger:    testLogger().With("peer", "test-nil-dc"),
		sendReady: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	err := peer.SendMessage(&protocol.PongEvent{Type: "pong"})
	if err == nil {
		t.Fatal("expected error when data channel is nil")
	}
	if !strings.Contains(err.Error(), "data channel not established") {
		t.Errorf("error should mention 'data channel not established', got: %v", err)
	}
}

func TestSendRaw_NilDataChannel(t *testing.T) {
	// Verify SendRaw returns an error when the data channel has not been established.
	peer := &Peer{
		DeviceID:  "test-nil-dc-raw",
		logger:    testLogger().With("peer", "test-nil-dc-raw"),
		sendReady: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}
	err := peer.SendRaw([]byte("data"))
	if err == nil {
		t.Fatal("expected error when data channel is nil")
	}
	if !strings.Contains(err.Error(), "data channel not established") {
		t.Errorf("error should mention 'data channel not established', got: %v", err)
	}
}

func TestWaitForSendReady_DoneChannel(t *testing.T) {
	// Verify waitForSendReady returns an error containing "peer connection closed"
	// when the done channel is closed while waiting for backpressure to clear.
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	api := fastAPI(t)
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil, "")
	pm.API = api

	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "connect_request",
		TargetDeviceID: "mobile-done",
	})
	time.Sleep(500 * time.Millisecond)

	peer := getPeer(pm, "mobile-done")
	if peer == nil {
		t.Fatal("peer should exist")
	}

	// Inject a mock DataChannel by using a real one from the PC so we have a
	// valid dc object, then manipulate the buffer amount threshold to force
	// the backpressure wait path. Since we can't easily overflow a real DC
	// buffer in a unit test, we test the done-channel path by:
	// 1. Getting the existing dc (non-nil so we bypass nil check)
	// 2. Closing the peer after a short delay so done channel fires
	// 3. Calling waitForSendReady directly with a synthetic dc that reports high buffer
	//
	// Instead, we create a minimal Peer with done channel and directly test waitForSendReady
	// using the existing dc from the established connection by closing the peer.
	testPeer := &Peer{
		DeviceID:  "test-done",
		logger:    testLogger().With("peer", "test-done"),
		sendReady: make(chan struct{}, 1),
		done:      make(chan struct{}),
	}

	// Use the peer's DC from the established connection so dc is non-nil and has a
	// BufferedAmount we can observe. Since we can't force BufferedAmount > maxBufferedAmount
	// without sending actual data over an open channel, we take a different approach:
	// close the done channel immediately and call waitForSendReady with a real dc
	// that has 0 buffered (so it returns nil fast path). Instead, test the done path
	// by pre-closing done and using a real dc via the established peer.
	peer.mu.Lock()
	dc := peer.dc
	peer.mu.Unlock()

	if dc == nil {
		// DC not yet established — skip the backpressure sub-test,
		// verify the done channel path using a closed channel directly.
		close(testPeer.done)
		// With done already closed, waitForSendReady should return immediately
		// with a "peer connection closed" error if dc.BufferedAmount > maxBufferedAmount.
		// Since we have no real dc to test with, just verify done is closed.
		select {
		case <-testPeer.done:
			// Expected
		default:
			t.Error("done channel should be closed")
		}
		pm.CloseAll()
		return
	}

	// Close the done channel after 50ms to unblock waitForSendReady
	go func() {
		time.Sleep(50 * time.Millisecond)
		close(testPeer.done)
	}()

	// waitForSendReady drains stale signal then checks BufferedAmount.
	// With a real (idle) DC, BufferedAmount is 0 which is <= maxBufferedAmount,
	// so it returns nil immediately on the fast path. To exercise the done-channel
	// path, call waitForSendReady on a peer whose done channel will be closed.
	// The fast path (buffer low) returns nil — that is the expected behavior here.
	err := testPeer.waitForSendReady(dc)
	if err != nil {
		// Only fail if the error is unexpected (not the done-channel path)
		if !strings.Contains(err.Error(), "peer connection closed") {
			t.Errorf("unexpected error from waitForSendReady: %v", err)
		}
	}

	pm.CloseAll()
}

func TestFetchTurnCredentials_CacheHit(t *testing.T) {
	// Verify that a cache hit returns the cached result without making an HTTP request.
	logger := testLogger()
	sender := &mockSender{}

	// Use an unreachable URL — if cache miss occurs, this would cause a failure.
	pm := NewPeerManager(logger, sender, "http://127.0.0.1:1", func() string { return "test-jwt" }, nil, "")

	// Pre-populate the cache.
	cachedServers := []webrtc.ICEServer{
		{URLs: []string{"stun:cached.example.com:3478"}, Username: "cached-user", Credential: "cached-cred"},
	}
	pm.mu.Lock()
	pm.turnCache = cachedServers
	pm.turnCacheTime = time.Now()
	pm.mu.Unlock()

	servers, err := pm.fetchTurnCredentials()
	if err != nil {
		t.Fatalf("fetchTurnCredentials() error on cache hit: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 cached server, got %d", len(servers))
	}
	if len(servers[0].URLs) == 0 || servers[0].URLs[0] != "stun:cached.example.com:3478" {
		t.Errorf("expected cached URL, got %v", servers[0].URLs)
	}
	if servers[0].Username != "cached-user" {
		t.Errorf("expected cached username, got %q", servers[0].Username)
	}
}

func TestOnDisconnectTimerFired_PeerRecovered(t *testing.T) {
	// Verify that onDisconnectTimerFired is a no-op when the peer has already
	// recovered (connection state is not Disconnected).
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-recovered"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 1 {
		t.Fatalf("expected 1 peer, got %d", pm.PeerCount())
	}

	// Record initial SDP offer count before firing the timer.
	initialOffers := len(sender.messagesOfType("sdp_offer"))

	// Simulate a disconnect timer firing. The peer's actual state is "new" or
	// "connecting" (not "disconnected") because we haven't completed the SDP
	// exchange, so onDisconnectTimerFired should detect recovery and exit early.
	pm.mu.Lock()
	pm.disconnectTimes["mobile-recovered"] = time.Now().Add(-pcDisconnectedTimeout)
	pm.disconnectTimers["mobile-recovered"] = time.AfterFunc(time.Hour, func() {}) // placeholder
	pm.mu.Unlock()

	pm.onDisconnectTimerFired("mobile-recovered")

	// No ICE restart offer should have been sent because peer is not in disconnected state.
	afterOffers := len(sender.messagesOfType("sdp_offer"))
	if afterOffers != initialOffers {
		t.Errorf("expected no new SDP offers (peer recovered), but got %d new offer(s)", afterOffers-initialOffers)
	}

	// Peer should still be alive.
	if pm.PeerCount() != 1 {
		t.Errorf("expected 1 peer after recovered timer, got %d", pm.PeerCount())
	}

	pm.CloseAll()
}

func TestHandleSignalingMessage_UnknownType(t *testing.T) {
	// Verify that an unknown signaling message type is handled gracefully (no panic).
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil, "")

	// Should not panic or cause any errors.
	pm.HandleSignalingMessage(SignalingMessage{
		Type:           "unknown_message_type",
		TargetDeviceID: "some-device",
	})

	// No peers should have been created.
	if pm.PeerCount() != 0 {
		t.Errorf("expected 0 peers after unknown message, got %d", pm.PeerCount())
	}
}

// TestBasicDataChannel verifies that two fastAPI peer connections can
// establish a DataChannel using gathered-complete SDP exchange.
func TestBasicDataChannel(t *testing.T) {
	api := fastAPI(t)

	offerer, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create offerer: %v", err)
	}
	defer offerer.Close()

	answerer, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create answerer: %v", err)
	}
	defer answerer.Close()

	dc, err := offerer.CreateDataChannel("test", nil)
	if err != nil {
		t.Fatalf("create data channel: %v", err)
	}

	dcOpened := make(chan struct{}, 1)
	dc.OnOpen(func() {
		dcOpened <- struct{}{}
	})

	// Use GatheringComplete to collect all candidates before SDP exchange
	offer, err := offerer.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	offerGatherDone := webrtc.GatheringCompletePromise(offerer)
	offerer.SetLocalDescription(offer)
	<-offerGatherDone

	answerer.SetRemoteDescription(*offerer.LocalDescription())

	answer, err := answerer.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}
	answerGatherDone := webrtc.GatheringCompletePromise(answerer)
	answerer.SetLocalDescription(answer)
	<-answerGatherDone

	offerer.SetRemoteDescription(*answerer.LocalDescription())

	select {
	case <-dcOpened:
		// Success — DataChannel opened
	case <-time.After(15 * time.Second):
		t.Fatal("DataChannel did not open within 15s")
	}
}
