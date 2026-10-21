package webrtc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
)

// testMobileAuth is the test-side mobile half of the AUTH V2 handshake. It
// derives the transcript from its own PeerConnection's DTLS view (its local
// certificate fingerprint and the SHA-256 of the certificate the agent
// presented), independently of the agent's view, so a passing handshake proves
// both ends bind the same certificates.
type testMobileAuth struct {
	pc     *webrtc.PeerConnection
	secret []byte

	mu          sync.Mutex
	hostNonce   []byte
	mobileNonce []byte
	hostFp      []byte
	mobileFp    []byte
}

// respond builds the encoded auth_response for an auth_challenge.
func (m *testMobileAuth) respond(ch *protocol.AuthChallengeEvent) ([]byte, error) {
	hostNonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode challenge nonce: %w", err)
	}
	mobileNonce := make([]byte, authNonceSize)
	if _, err := rand.Read(mobileNonce); err != nil {
		return nil, fmt.Errorf("generate mobile nonce: %w", err)
	}
	// From the mobile's side, its own certificate is local and the host's is remote.
	mobileFp, hostFp, err := pcDTLSFingerprints(m.pc)
	if err != nil {
		return nil, fmt.Errorf("mobile DTLS fingerprints: %w", err)
	}

	m.mu.Lock()
	m.hostNonce, m.mobileNonce, m.hostFp, m.mobileFp = hostNonce, mobileNonce, hostFp, mobileFp
	m.mu.Unlock()

	return protocol.Encode(&protocol.AuthResponseRequest{
		Type:  "auth_response",
		Mac:   base64.StdEncoding.EncodeToString(authMAC(m.secret, authLabelMobileToHost, hostNonce, mobileNonce, hostFp, mobileFp)),
		Nonce: base64.StdEncoding.EncodeToString(mobileNonce),
	})
}

// verifyConfirm reports whether an auth_confirm MAC proves the host holds the
// shared secret for this connection's transcript.
func (m *testMobileAuth) verifyConfirm(ev *protocol.AuthConfirmEvent) bool {
	got, err := base64.StdEncoding.DecodeString(ev.Mac)
	if err != nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hostNonce == nil {
		return false
	}
	want := authMAC(m.secret, authLabelHostToMobile, m.hostNonce, m.mobileNonce, m.hostFp, m.mobileFp)
	return hmac.Equal(want, got)
}

// handle processes a DataChannel message on the test mobile. It answers an
// auth_challenge and reports an auth_confirm on confirmed (true when it
// verifies). It returns true if the message was part of the handshake.
func (m *testMobileAuth) handle(t *testing.T, dc *webrtc.DataChannel, data []byte, confirmed chan<- bool) bool {
	decoded, err := protocol.Decode(data)
	if err != nil {
		return false
	}
	switch ev := decoded.(type) {
	case *protocol.AuthChallengeEvent:
		resp, err := m.respond(ev)
		if err != nil {
			t.Errorf("test mobile: %v", err)
			return true
		}
		if err := dc.Send(resp); err != nil {
			t.Errorf("test mobile: send auth_response: %v", err)
		}
		return true
	case *protocol.AuthConfirmEvent:
		select {
		case confirmed <- m.verifyConfirm(ev):
		default:
		}
		return true
	}
	return false
}

// testMobile is a test-side mobile connected to a PeerManager over a real
// loopback PeerConnection. It records every DataChannel message it receives,
// in arrival order, and runs the mobile half of the AUTH V2 handshake.
type testMobile struct {
	t           *testing.T
	pc          *webrtc.PeerConnection
	auth        *testMobileAuth
	autoRespond bool // answer auth_challenge immediately; otherwise hold it on challenges

	challenges chan *protocol.AuthChallengeEvent // held challenges (autoRespond false)
	confirmed  chan bool                         // auth_confirm verification results

	mu       sync.Mutex
	dc       *webrtc.DataChannel
	received []protocol.Message
}

// connectTestMobile sends a connect_request for deviceID and completes the SDP
// and ICE exchange from the mobile side. Only signaling sent after this call
// is used, so it also works for a reconnect that replaces an existing peer.
func connectTestMobile(t *testing.T, pm *PeerManager, sender *mockSender, deviceID string, autoRespond bool) *testMobile {
	t.Helper()
	mark := sender.mark()
	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: deviceID})
	offers := sender.messagesOfTypeSince("sdp_offer", mark)
	if len(offers) == 0 {
		t.Fatalf("no SDP offer sent to %s", deviceID)
	}

	pc, err := pm.API.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create mobile PC: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	m := &testMobile{
		t:           t,
		pc:          pc,
		auth:        &testMobileAuth{pc: pc, secret: testSharedSecret},
		autoRespond: autoRespond,
		challenges:  make(chan *protocol.AuthChallengeEvent, 1),
		confirmed:   make(chan bool, 1),
	}
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		m.mu.Lock()
		m.dc = dc
		m.mu.Unlock()
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			m.receive(dc, msg.Data)
		})
	})

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offers[0].SDP}); err != nil {
		t.Fatalf("set remote offer: %v", err)
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		t.Fatalf("set local answer: %v", err)
	}
	<-gathered
	// The gathered answer carries the mobile's candidates in its SDP.
	pm.HandleSignalingMessage(SignalingMessage{Type: "sdp_answer", TargetDeviceID: deviceID, SDP: pc.LocalDescription().SDP})

	// Trickle the agent's candidates to the mobile until the test ends.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		seen := make(map[string]bool)
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			for _, msg := range sender.messagesOfTypeSince("ice_candidate", mark) {
				if msg.TargetDeviceID != deviceID || seen[msg.Candidate] {
					continue
				}
				seen[msg.Candidate] = true
				var mIdx *uint16
				if msg.SDPMLineIndex != nil {
					v := uint16(*msg.SDPMLineIndex)
					mIdx = &v
				}
				mid := msg.SDPMid
				_ = pc.AddICECandidate(webrtc.ICECandidateInit{Candidate: msg.Candidate, SDPMid: &mid, SDPMLineIndex: mIdx})
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		wg.Wait()
	})
	return m
}

// receive records an incoming message and drives the mobile's handshake.
func (m *testMobile) receive(dc *webrtc.DataChannel, data []byte) {
	decoded, err := protocol.Decode(data)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.received = append(m.received, decoded)
	m.mu.Unlock()

	switch ev := decoded.(type) {
	case *protocol.AuthChallengeEvent:
		if !m.autoRespond {
			select {
			case m.challenges <- ev:
			default:
			}
			return
		}
		m.respond(dc, ev)
	case *protocol.AuthConfirmEvent:
		select {
		case m.confirmed <- m.auth.verifyConfirm(ev):
		default:
		}
	}
}

// respond sends the auth_response for a challenge.
func (m *testMobile) respond(dc *webrtc.DataChannel, ch *protocol.AuthChallengeEvent) {
	resp, err := m.auth.respond(ch)
	if err != nil {
		m.t.Errorf("test mobile: %v", err)
		return
	}
	if err := dc.Send(resp); err != nil {
		m.t.Errorf("test mobile: send auth_response: %v", err)
	}
}

// send encodes and sends a request to the agent.
func (m *testMobile) send(msg protocol.Message) {
	m.t.Helper()
	m.mu.Lock()
	dc := m.dc
	m.mu.Unlock()
	if dc == nil {
		m.t.Fatal("test mobile: DataChannel not open")
	}
	data, err := protocol.Encode(msg)
	if err != nil {
		m.t.Fatalf("test mobile: encode %s: %v", msg.MessageType(), err)
	}
	if err := dc.Send(data); err != nil {
		m.t.Fatalf("test mobile: send %s: %v", msg.MessageType(), err)
	}
}

// waitConfirmed waits for the agent's auth_confirm and requires it to verify.
func (m *testMobile) waitConfirmed() {
	m.t.Helper()
	select {
	case ok := <-m.confirmed:
		if !ok {
			m.t.Fatal("auth_confirm from the agent did not verify on the mobile")
		}
	case <-time.After(15 * time.Second):
		m.t.Fatal("no auth_confirm received from the agent")
	}
}

// types returns the types of the messages received so far, in order.
func (m *testMobile) types() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	types := make([]string, len(m.received))
	for i, msg := range m.received {
		types[i] = msg.MessageType()
	}
	return types
}

// outputs returns the data of every output event received so far, in order.
func (m *testMobile) outputs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var outs []string
	for _, msg := range m.received {
		if ev, ok := msg.(*protocol.OutputEvent); ok {
			outs = append(outs, string(ev.Data))
		}
	}
	return outs
}

// waitUntil polls cond until it holds or the timeout expires.
func waitUntil(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// newAuthTestManager returns a PeerManager that accepts deviceID, using loopback
// ICE and the test shared secret.
func newAuthTestManager(t *testing.T, sender *mockSender, deviceID string, handler ProtocolHandler) *PeerManager {
	t.Helper()
	pm := NewPeerManager(testLogger(), sender, "http://localhost:1", func() string { return "jwt" }, handler, "")
	pm.API = fastAPI(t)
	pm.SetAllowedDeviceID(deviceID)
	pm.SharedSecretFn = testSharedSecretFn
	return pm
}

// fixedBytes returns n copies of b.
func fixedBytes(b byte, n int) []byte {
	return bytes.Repeat([]byte{b}, n)
}

func TestAuthMAC_TestVector(t *testing.T) {
	secret := fixedBytes(0x33, 32)
	hostNonce := fixedBytes(0x44, 32)
	mobileNonce := fixedBytes(0x55, 32)
	hostFp := fixedBytes(0x66, 32)
	mobileFp := fixedBytes(0x77, 32)

	tests := []struct {
		name  string
		label string
		want  string
	}{
		{name: "auth_response", label: authLabelMobileToHost, want: "SRmZqK30zbyLEF1cxC3rbsBh5PuWr6xxlITXx3m88GA="},
		{name: "auth_confirm", label: authLabelHostToMobile, want: "/qx2TPaChB28lQREbWga+vO5UENi9/hLUmuFaKqVWkQ="},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := base64.StdEncoding.EncodeToString(authMAC(secret, tt.label, hostNonce, mobileNonce, hostFp, mobileFp))
			if got != tt.want {
				t.Errorf("authMAC = %q, want %q", got, tt.want)
			}
		})
	}
}

// Fixed transcript inputs for the verifier unit tests.
var (
	testHostNonce   = fixedBytes(0x01, authNonceSize)
	testMobileNonce = fixedBytes(0x02, authNonceSize)
	testHostFp      = fixedBytes(0x03, sha256.Size)
	testMobileFp    = fixedBytes(0x04, sha256.Size)
)

// useFakeDTLSFingerprints makes the verifier see fixed DTLS fingerprints so it
// can be exercised without a connected PeerConnection.
func useFakeDTLSFingerprints(t *testing.T, hostFp, mobileFp []byte, err error) {
	t.Helper()
	orig := peerDTLSFingerprints
	peerDTLSFingerprints = func(*Peer) ([]byte, []byte, error) { return hostFp, mobileFp, err }
	t.Cleanup(func() { peerDTLSFingerprints = orig })
}

// useSucceedingConfirmSend makes auth_confirm sends succeed without a
// DataChannel, so a valid response completes the handshake.
func useSucceedingConfirmSend(t *testing.T) {
	t.Helper()
	orig := peerSendAuthConfirm
	peerSendAuthConfirm = func(*Peer, protocol.Message) error { return nil }
	t.Cleanup(func() { peerSendAuthConfirm = orig })
}

// validAuthResponse builds an auth_response that verifies against the fixed
// transcript inputs.
func validAuthResponse() *protocol.AuthResponseRequest {
	return &protocol.AuthResponseRequest{
		Type:  "auth_response",
		Mac:   base64.StdEncoding.EncodeToString(authMAC(testSharedSecret, authLabelMobileToHost, testHostNonce, testMobileNonce, testHostFp, testMobileFp)),
		Nonce: base64.StdEncoding.EncodeToString(testMobileNonce),
	}
}

// newAuthTestPeer builds a minimal Peer suitable for exercising the auth gate
// directly (no real PeerConnection). pm is nil, so failAuth closes via p.Close(),
// which tolerates a nil conn.
func newAuthTestPeer(nonce []byte) *Peer {
	return &Peer{
		DeviceID:     "mobile-auth",
		logger:       testLogger(),
		sharedSecret: testSharedSecret,
		authNonce:    nonce,
		sendReady:    make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
}

func TestPeer_VerifyAuthResponse(t *testing.T) {
	v1MAC := hmac.New(sha256.New, testSharedSecret)
	v1MAC.Write(testHostNonce)
	b64 := base64.StdEncoding.EncodeToString

	tests := []struct {
		name     string
		msg      protocol.Message
		fpErr    error
		wantAuth bool
	}{
		{
			name:     "valid v2 response authenticates",
			msg:      validAuthResponse(),
			wantAuth: true,
		},
		{
			name:     "v1 MAC over the challenge nonce only is rejected",
			msg:      &protocol.AuthResponseRequest{Type: "auth_response", Mac: b64(v1MAC.Sum(nil)), Nonce: b64(testMobileNonce)},
			wantAuth: false,
		},
		{
			name: "reflected host->mobile MAC is rejected",
			msg: &protocol.AuthResponseRequest{
				Type:  "auth_response",
				Mac:   b64(authMAC(testSharedSecret, authLabelHostToMobile, testHostNonce, testMobileNonce, testHostFp, testMobileFp)),
				Nonce: b64(testMobileNonce),
			},
			wantAuth: false,
		},
		{
			name: "MAC over a different mobile certificate is rejected",
			msg: &protocol.AuthResponseRequest{
				Type:  "auth_response",
				Mac:   b64(authMAC(testSharedSecret, authLabelMobileToHost, testHostNonce, testMobileNonce, testHostFp, fixedBytes(0x05, sha256.Size))),
				Nonce: b64(testMobileNonce),
			},
			wantAuth: false,
		},
		{
			name: "MAC over a different host certificate is rejected",
			msg: &protocol.AuthResponseRequest{
				Type:  "auth_response",
				Mac:   b64(authMAC(testSharedSecret, authLabelMobileToHost, testHostNonce, testMobileNonce, fixedBytes(0x05, sha256.Size), testMobileFp)),
				Nonce: b64(testMobileNonce),
			},
			wantAuth: false,
		},
		{
			name: "MAC under the wrong shared secret is rejected",
			msg: &protocol.AuthResponseRequest{
				Type:  "auth_response",
				Mac:   b64(authMAC(fixedBytes(0x99, 32), authLabelMobileToHost, testHostNonce, testMobileNonce, testHostFp, testMobileFp)),
				Nonce: b64(testMobileNonce),
			},
			wantAuth: false,
		},
		{
			name: "mobile nonce that is not 32 bytes is rejected",
			msg: &protocol.AuthResponseRequest{
				Type:  "auth_response",
				Mac:   b64(authMAC(testSharedSecret, authLabelMobileToHost, testHostNonce, testMobileNonce[:16], testHostFp, testMobileFp)),
				Nonce: b64(testMobileNonce[:16]),
			},
			wantAuth: false,
		},
		{
			name:     "missing mobile nonce is rejected",
			msg:      &protocol.AuthResponseRequest{Type: "auth_response", Mac: validAuthResponse().Mac},
			wantAuth: false,
		},
		{
			name:     "mobile nonce that is not base64 is rejected",
			msg:      &protocol.AuthResponseRequest{Type: "auth_response", Mac: validAuthResponse().Mac, Nonce: "not base64!"},
			wantAuth: false,
		},
		{
			name:     "MAC that is not base64 is rejected",
			msg:      &protocol.AuthResponseRequest{Type: "auth_response", Mac: "not base64!", Nonce: b64(testMobileNonce)},
			wantAuth: false,
		},
		{
			name:     "unavailable DTLS fingerprints fail closed",
			msg:      validAuthResponse(),
			fpErr:    fmt.Errorf("no remote DTLS certificate"),
			wantAuth: false,
		},
		{
			name:     "first message that is not auth_response is rejected",
			msg:      &protocol.PingRequest{Type: "ping"},
			wantAuth: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFakeDTLSFingerprints(t, testHostFp, testMobileFp, tt.fpErr)
			useSucceedingConfirmSend(t)
			p := newAuthTestPeer(testHostNonce)

			p.verifyAuthResponse(tt.msg)

			p.mu.Lock()
			defer p.mu.Unlock()
			if p.authenticated != tt.wantAuth {
				t.Errorf("authenticated = %v, want %v", p.authenticated, tt.wantAuth)
			}
			if !p.authResolved {
				t.Error("auth must be resolved after a response either way")
			}
		})
	}
}

// TestPeer_VerifyAuthResponse_ConfirmSendFailureClosesPeer covers a peer that
// authenticates but cannot be sent auth_confirm (here: no DataChannel). It must
// not be marked confirmed, must have authenticated revoked so no further
// request reaches the handler, and must be torn down, since failAuth no longer
// applies once auth has resolved.
func TestPeer_VerifyAuthResponse_ConfirmSendFailureClosesPeer(t *testing.T) {
	useFakeDTLSFingerprints(t, testHostFp, testMobileFp, nil)
	p := newAuthTestPeer(testHostNonce)

	p.verifyAuthResponse(validAuthResponse())

	select {
	case <-p.done:
	case <-time.After(2 * time.Second):
		t.Fatal("peer was not closed after auth_confirm send failed")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authenticated {
		t.Error("authenticated must be revoked when auth_confirm was not sent")
	}
	if p.authConfirmed {
		t.Error("authConfirmed must stay false when auth_confirm was not sent")
	}
}

func TestPeer_FailAuthNoOpAfterSuccess(t *testing.T) {
	useFakeDTLSFingerprints(t, testHostFp, testMobileFp, nil)
	useSucceedingConfirmSend(t)
	p := newAuthTestPeer(testHostNonce)

	p.verifyAuthResponse(validAuthResponse())

	p.mu.Lock()
	if !p.authenticated || !p.authResolved {
		p.mu.Unlock()
		t.Fatal("expected authenticated and resolved after a valid response")
	}
	p.mu.Unlock()

	// A late timeout must not tear down a peer that already authenticated.
	p.failAuth("authentication timeout")

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.authenticated {
		t.Fatal("failAuth after a successful handshake must be a no-op")
	}
}

func TestPeer_VerifySuccessIgnoredAfterFailAuth(t *testing.T) {
	useFakeDTLSFingerprints(t, testHostFp, testMobileFp, nil)
	p := newAuthTestPeer(testHostNonce)

	// The timeout resolves auth first, and the challenge nonce is dropped.
	p.failAuth("authentication timeout")
	p.mu.Lock()
	nonceCleared := p.authNonce == nil
	p.mu.Unlock()
	if !nonceCleared {
		t.Fatal("failAuth must clear the challenge nonce")
	}

	// A valid response arriving afterwards must NOT flip authenticated or send
	// auth_confirm — the peer is already being torn down.
	p.verifyAuthResponse(validAuthResponse())

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authenticated {
		t.Fatal("a valid response after failAuth must be ignored")
	}
	if p.authConfirmed {
		t.Fatal("auth_confirm must not be sent after failAuth")
	}
}

func TestPeer_DTLSFingerprints_NoConnection(t *testing.T) {
	p := newAuthTestPeer(testHostNonce)
	if _, _, err := p.dtlsFingerprints(); err == nil {
		t.Fatal("expected an error for a peer without a PeerConnection")
	}
}

func TestPCDTLSFingerprints_BeforeHandshake(t *testing.T) {
	pc, err := fastAPI(t).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create PC: %v", err)
	}
	defer pc.Close()

	if _, _, err := pcDTLSFingerprints(pc); err == nil {
		t.Fatal("expected an error before the DTLS handshake has selected a remote certificate")
	}
}

// TestPeer_FailAuthTeardown checks that failAuth closes the failing peer and
// fires the disconnect handler only while that peer is still the one tracked
// under its device ID. A stale peer's failure (after a reconnect replaced it)
// must neither evict the replacement nor tear down the replacement's handler
// state, which is keyed by the same device ID.
func TestPeer_FailAuthTeardown(t *testing.T) {
	tests := []struct {
		name      string
		current   bool // the failing peer is tracked under its device ID
		closing   bool // CloseAll has already run
		wantFires int
	}{
		{name: "current peer fires disconnect and is removed", current: true, wantFires: 1},
		{name: "stale peer leaves the replacement alone", current: false, wantFires: 0},
		{name: "closing manager closes the peer without firing", closing: true, wantFires: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := NewPeerManager(testLogger(), &mockSender{}, "http://localhost:1", func() string { return "jwt" }, nil, "")
			var mu sync.Mutex
			var fired []string
			pm.OnPeerDisconnect = func(id string) {
				mu.Lock()
				fired = append(fired, id)
				mu.Unlock()
			}

			failing := &Peer{DeviceID: "m", pm: pm, logger: testLogger(), sendReady: make(chan struct{}, 1), done: make(chan struct{})}
			replacement := &Peer{DeviceID: "m", logger: testLogger(), sendReady: make(chan struct{}, 1), done: make(chan struct{})}
			var wantTracked *Peer
			switch {
			case tt.closing:
				pm.CloseAll()
			case tt.current:
				pm.mu.Lock()
				pm.peers["m"] = failing
				pm.mu.Unlock()
			default:
				pm.mu.Lock()
				pm.peers["m"] = replacement
				pm.mu.Unlock()
				wantTracked = replacement
			}

			failing.failAuth("authentication timeout")
			// failAuth registers its teardown with cleanupWg before returning.
			pm.cleanupWg.Wait()

			select {
			case <-failing.done:
			case <-time.After(2 * time.Second):
				t.Fatal("failing peer was not closed")
			}
			select {
			case <-replacement.done:
				t.Error("failAuth closed the replacement peer")
			default:
			}

			mu.Lock()
			gotFired := append([]string(nil), fired...)
			mu.Unlock()
			if len(gotFired) != tt.wantFires {
				t.Errorf("OnPeerDisconnect fired %d times (%v), want %d", len(gotFired), gotFired, tt.wantFires)
			}
			for _, id := range gotFired {
				if id != "m" {
					t.Errorf("OnPeerDisconnect fired for %q, want %q", id, "m")
				}
			}
			if got := getPeer(pm, "m"); got != wantTracked {
				t.Errorf("tracked peer after failAuth = %p, want %p", got, wantTracked)
			}
		})
	}
}

// TestPeer_SendMessageAuthGate checks that, until auth_confirm has been sent,
// SendMessage refuses everything except the host's handshake messages.
func TestPeer_SendMessageAuthGate(t *testing.T) {
	pc, err := fastAPI(t).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create PC: %v", err)
	}
	defer pc.Close()
	// The channel never opens, so messages that pass the gate fail in dc.Send
	// with a different error; only the gate's refusal is asserted here.
	dc, err := pc.CreateDataChannel(DataChannelLabel, nil)
	if err != nil {
		t.Fatalf("create DataChannel: %v", err)
	}

	tests := []struct {
		name          string
		msg           protocol.Message
		authConfirmed bool
		wantRefused   bool
	}{
		{name: "pong before confirm is refused", msg: &protocol.PongEvent{Type: "pong"}, wantRefused: true},
		{name: "output before confirm is refused", msg: &protocol.OutputEvent{Type: "output", Data: []byte("x")}, wantRefused: true},
		{name: "sessions before confirm is refused", msg: &protocol.SessionsEvent{Type: "sessions"}, wantRefused: true},
		{name: "auth_challenge before confirm is allowed", msg: &protocol.AuthChallengeEvent{Type: "auth_challenge", Nonce: "n"}},
		{name: "auth_confirm before confirm is allowed", msg: &protocol.AuthConfirmEvent{Type: "auth_confirm", Mac: "m"}},
		{name: "pong after confirm is allowed", msg: &protocol.PongEvent{Type: "pong"}, authConfirmed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newAuthTestPeer(nil)
			p.dc = dc
			p.authConfirmed = tt.authConfirmed

			err := p.SendMessage(tt.msg)
			refused := err != nil && strings.Contains(err.Error(), "peer not authenticated")
			if refused != tt.wantRefused {
				t.Errorf("SendMessage(%s) err = %v; refused = %v, want %v", tt.msg.MessageType(), err, refused, tt.wantRefused)
			}
		})
	}

	t.Run("SendRaw before confirm is refused", func(t *testing.T) {
		p := newAuthTestPeer(nil)
		p.dc = dc
		if err := p.SendRaw([]byte("x")); err == nil || !strings.Contains(err.Error(), "peer not authenticated") {
			t.Errorf("SendRaw err = %v, want a peer not authenticated error", err)
		}
	})
}

// TestPeerManager_UndecodableMessageBeforeAuthClosesPeer checks that a pre-auth
// message that fails to decode frees the single peer slot immediately rather
// than at authChallengeTimeout.
func TestPeerManager_UndecodableMessageBeforeAuthClosesPeer(t *testing.T) {
	const deviceID = "mobile-undecodable"
	sender := &mockSender{}
	pm := newAuthTestManager(t, sender, deviceID, nil)
	defer pm.CloseAll()

	m := connectTestMobile(t, pm, sender, deviceID, false)
	select {
	case <-m.challenges:
	case <-time.After(15 * time.Second):
		t.Fatal("no auth_challenge received")
	}

	m.mu.Lock()
	dc := m.dc
	m.mu.Unlock()
	if err := dc.Send([]byte{0xc1}); err != nil { // 0xc1 is never valid MessagePack
		t.Fatalf("send: %v", err)
	}

	waitUntil(t, authChallengeTimeout/2, "peer to be removed", func() bool {
		return getPeer(pm, deviceID) == nil
	})
}

// TestPeerManager_SendToRefusedUntilAuthConfirmed holds the mobile's
// auth_response so the pre-auth window is deterministic: the challenge still
// goes out, any other message is refused without reaching the DataChannel, and
// the gate lifts only once auth_confirm has been sent.
func TestPeerManager_SendToRefusedUntilAuthConfirmed(t *testing.T) {
	const deviceID = "mobile-gate"
	sender := &mockSender{}
	pm := newAuthTestManager(t, sender, deviceID, nil)
	defer pm.CloseAll()

	m := connectTestMobile(t, pm, sender, deviceID, false)

	var ch *protocol.AuthChallengeEvent
	select {
	case ch = <-m.challenges:
	case <-time.After(15 * time.Second):
		t.Fatal("no auth_challenge received before authentication")
	}

	pong := &protocol.PongEvent{Type: "pong"}
	err := pm.SendTo(deviceID, pong)
	if err == nil || !strings.Contains(err.Error(), "peer not authenticated") {
		t.Fatalf("SendTo before auth: err = %v, want a peer not authenticated error", err)
	}
	// Give anything wrongly written to the DataChannel time to arrive.
	time.Sleep(200 * time.Millisecond)
	if got := m.types(); len(got) != 1 || got[0] != "auth_challenge" {
		t.Fatalf("mobile received %v before answering the challenge, want [auth_challenge]", got)
	}

	m.mu.Lock()
	dc := m.dc
	m.mu.Unlock()
	m.respond(dc, ch)
	m.waitConfirmed()

	// authConfirmed is set once the auth_confirm send returns, so poll.
	waitUntil(t, 2*time.Second, "SendTo to succeed after auth_confirm", func() bool {
		return pm.SendTo(deviceID, pong) == nil
	})
	waitUntil(t, 5*time.Second, "pong delivery", func() bool { return len(m.types()) >= 3 })

	got := m.types()
	if got[0] != "auth_challenge" || got[1] != "auth_confirm" {
		t.Fatalf("mobile received %v, want auth_challenge then auth_confirm first", got)
	}
	for _, typ := range got[2:] {
		if typ != "pong" {
			t.Fatalf("unexpected %s after the handshake in %v", typ, got)
		}
	}
}

// TestPeerManager_AuthConfirmFirstAfterHandshake hammers SendTo across the
// whole handshake. Nothing may reach the mobile ahead of the handshake
// messages: the first message after its auth_response must be auth_confirm.
func TestPeerManager_AuthConfirmFirstAfterHandshake(t *testing.T) {
	const deviceID = "mobile-hammer"
	sender := &mockSender{}
	pm := newAuthTestManager(t, sender, deviceID, nil)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pong := &protocol.PongEvent{Type: "pong"}
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = pm.SendTo(deviceID, pong)
			runtime.Gosched()
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
		pm.CloseAll()
	}()

	m := connectTestMobile(t, pm, sender, deviceID, true)
	m.waitConfirmed()
	// Pongs flowing afterwards show the hammer was live and the gate lifted.
	waitUntil(t, 5*time.Second, "pongs after auth_confirm", func() bool { return len(m.types()) >= 3 })

	got := m.types()
	if got[0] != "auth_challenge" || got[1] != "auth_confirm" {
		t.Fatalf("mobile received %v, want auth_challenge then auth_confirm first", got)
	}
	for _, typ := range got[2:] {
		if typ != "pong" {
			t.Fatalf("unexpected %s after the handshake in %v", typ, got)
		}
	}
}

// TestPeerManager_RejectsWhenSharedSecretUnavailable verifies the connect-time
// fail-closed behaviour: if the shared secret cannot be loaded, the agent cannot
// authenticate the peer, so the connection is rejected before any offer (SB-992).
func TestPeerManager_RejectsWhenSharedSecretUnavailable(t *testing.T) {
	sender := &mockSender{}
	pm := NewPeerManager(testLogger(), sender, "http://localhost:1", func() string { return "jwt" }, nil, "")
	pm.API = fastAPI(t)
	pm.SetAllowedDeviceID("mobile-nosecret")
	pm.SharedSecretFn = func(string) ([]byte, error) {
		return nil, fmt.Errorf("secret store unavailable")
	}

	pm.HandleSignalingMessage(SignalingMessage{Type: "connect_request", TargetDeviceID: "mobile-nosecret"})
	time.Sleep(200 * time.Millisecond)

	if pm.PeerCount() != 0 {
		t.Errorf("expected 0 peers when shared secret is unavailable, got %d", pm.PeerCount())
	}
	if len(sender.messagesOfType("sdp_offer")) != 0 {
		t.Error("no SDP offer should be sent when the peer cannot be authenticated")
	}
	rejected := false
	for _, m := range sender.messagesOfType("connection_rejected") {
		if m.TargetDeviceID == "mobile-nosecret" && m.Reason == "secret_unavailable" {
			rejected = true
		}
	}
	if !rejected {
		t.Error("expected connection_rejected with reason secret_unavailable sent to the device")
	}

	pm.CloseAll()
}
