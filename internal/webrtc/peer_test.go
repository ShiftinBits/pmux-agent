package webrtc

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
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

	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil)
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
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil)
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
	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, handler)
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

	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil)
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

func TestPeerManager_MultiplePeers(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()
	turnServer := mockTurnServer(t)
	defer turnServer.Close()

	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil)
	pm.API = fastAPI(t)

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m1"})
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m2"})
	time.Sleep(500 * time.Millisecond)

	pm.mu.Lock()
	count := len(pm.peers)
	pm.mu.Unlock()
	if count != 2 {
		t.Errorf("expected 2 peers, got %d", count)
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
	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "test-jwt" }, nil)
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

		pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil)
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

		pm := NewPeerManager(logger, sender, badServer.URL, func() string { return "test-jwt" }, nil)
		_, err := pm.fetchTurnCredentials()
		if err == nil {
			t.Error("expected error from bad TURN server")
		}
	})
}

func TestPeerManager_UnknownPeerMessages(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil)

	// These should not panic
	pm.HandleSignalingMessage(SignalingMessage{Type: "sdp_answer", TargetDeviceID: "nonexistent", SDP: "v=0"})
	pm.HandleSignalingMessage(SignalingMessage{Type: "ice_candidate", TargetDeviceID: "nonexistent", Candidate: "c"})
}

func TestPeerManager_SendTo(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil)

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

	pm := NewPeerManager(logger, sender, turnServer.URL, func() string { return "test-jwt" }, nil)
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

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil)
	pm.API = fastAPI(t)
	pm.MaxPeers = 2

	// Connect two peers (should succeed)
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m1"})
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m2"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 2 {
		t.Fatalf("expected 2 peers, got %d", pm.PeerCount())
	}

	// Third peer should be rejected
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m3"})
	time.Sleep(200 * time.Millisecond)

	if pm.PeerCount() != 2 {
		t.Errorf("expected 2 peers after rejection, got %d", pm.PeerCount())
	}

	// Verify error message was sent
	errors := sender.messagesOfType("error")
	found := false
	for _, e := range errors {
		if e.TargetDeviceID == "m3" && e.Error == "max connections reached" {
			found = true
		}
	}
	if !found {
		t.Error("expected error message sent to m3")
	}

	pm.CloseAll()
}

func TestPeerManager_ReconnectDoesNotExceedLimit(t *testing.T) {
	sender := &mockSender{}
	logger := testLogger()

	pm := NewPeerManager(logger, sender, "http://localhost:1", func() string { return "jwt" }, nil)
	pm.API = fastAPI(t)
	pm.MaxPeers = 2

	// Fill to capacity
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m1"})
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m2"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 2 {
		t.Fatalf("expected 2 peers, got %d", pm.PeerCount())
	}

	// m1 reconnecting should succeed (same device ID)
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "m1"})
	time.Sleep(500 * time.Millisecond)

	if pm.PeerCount() != 2 {
		t.Errorf("expected 2 peers after reconnect, got %d", pm.PeerCount())
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
