package webrtc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
)

// Fixed DTLS fingerprints for peers built without a real PeerConnection.
var (
	testOfferFP  = bytes.Repeat([]byte{0x03}, 32)
	testAnswerFP = bytes.Repeat([]byte{0x04}, 32)
)

// authMAC computes the base64 key-possession proof for a raw nonce, mirroring
// the agent's verifyAuthResponse and the mobile client.
func authMAC(secret, nonce []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(nonce)
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// authResponseForChallenge builds the base64 MAC response for a base64-encoded
// challenge nonce (the wire form). Used by the end-to-end handshake tests.
func authResponseForChallenge(secret []byte, nonceB64 string) string {
	nonce, _ := base64.StdEncoding.DecodeString(nonceB64)
	return authMAC(secret, nonce)
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
		authOfferFP:  testOfferFP,
		authAnswerFP: testAnswerFP,
		sendReady:    make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
}

// The valid-MAC cases use a real DataChannel: a successful verify only leaves
// the peer authenticated if the auth proof is actually sent.
func TestPeer_VerifyAuthResponse_ValidMACAuthenticates(t *testing.T) {
	l := newLoopbackAuthPeer(t)
	nonce := l.challenge(t)
	p := l.peer

	p.verifyAuthResponse(&protocol.AuthResponseRequest{
		Type: "auth_response",
		Mac:  authMAC(testSharedSecret, nonce),
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.authenticated {
		t.Fatal("peer with valid MAC should be authenticated")
	}
}

func TestPeer_VerifyAuthResponse_WrongMACDoesNotAuthenticate(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	p := newAuthTestPeer(nonce)

	// MAC computed over the wrong nonce — an attacker without the secret cannot
	// produce a valid proof.
	p.verifyAuthResponse(&protocol.AuthResponseRequest{
		Type: "auth_response",
		Mac:  authMAC(testSharedSecret, []byte("wrong-nonce-wrong-nonce-wrong-no")),
	})

	p.mu.Lock()
	authed := p.authenticated
	p.mu.Unlock()
	if authed {
		t.Fatal("peer with wrong MAC must not be authenticated")
	}
}

func TestPeer_VerifyAuthResponse_WrongTypeDoesNotAuthenticate(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	p := newAuthTestPeer(nonce)

	// First message is not an auth_response — must be rejected.
	p.verifyAuthResponse(&protocol.PingRequest{Type: "ping"})

	p.mu.Lock()
	authed := p.authenticated
	p.mu.Unlock()
	if authed {
		t.Fatal("peer whose first message is not auth_response must not be authenticated")
	}
}

func TestPeer_FailAuthNoOpAfterSuccess(t *testing.T) {
	l := newLoopbackAuthPeer(t)
	nonce := l.challenge(t)
	p := l.peer

	p.verifyAuthResponse(&protocol.AuthResponseRequest{
		Type: "auth_response",
		Mac:  authMAC(testSharedSecret, nonce),
	})

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
	nonce := []byte("0123456789abcdef0123456789abcdef")
	p := newAuthTestPeer(nonce)

	// The timeout resolves auth first.
	p.failAuth("authentication timeout")

	// A valid response arriving afterwards must NOT flip authenticated — the
	// peer is already being torn down.
	p.verifyAuthResponse(&protocol.AuthResponseRequest{
		Type: "auth_response",
		Mac:  authMAC(testSharedSecret, nonce),
	})

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.authenticated {
		t.Fatal("a valid response after failAuth must be ignored")
	}
}

// TestPeer_FailAuthDoesNotEvictReplacementPeer guards the reconnect-replace race:
// a stale peer's auth-failure teardown must not close the new peer that already
// replaced it under the same device ID.
func TestPeer_FailAuthDoesNotEvictReplacementPeer(t *testing.T) {
	pm := NewPeerManager(testLogger(), &mockSender{}, "http://localhost:1", func() string { return "jwt" }, nil, "")

	// The new peer currently tracked under the device ID.
	peerB := &Peer{DeviceID: "m", logger: testLogger(), sendReady: make(chan struct{}, 1), done: make(chan struct{})}
	pm.mu.Lock()
	pm.peers["m"] = peerB
	pm.mu.Unlock()

	// A stale peer A (same device ID, never inserted) fails auth.
	peerA := &Peer{DeviceID: "m", pm: pm, logger: testLogger(), sendReady: make(chan struct{}, 1), done: make(chan struct{})}
	peerA.failAuth("authentication timeout")

	// failAuth closes on a goroutine; wait for it to settle.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pm.mu.Lock()
		settled := pm.peers["m"] == peerB
		pm.mu.Unlock()
		if settled {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()
	if pm.peers["m"] != peerB {
		t.Fatal("failAuth on a stale peer must not evict the replacement peer")
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

// colonHex formats b the way an SDP a=fingerprint line does (lowercase).
func colonHex(b []byte) string {
	parts := make([]string, len(b))
	for i, c := range b {
		parts[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(parts, ":")
}

func TestSdpSHA256Fingerprint(t *testing.T) {
	fpA := make([]byte, 32)
	fpB := make([]byte, 32)
	for i := range fpA {
		fpA[i] = byte(0xA0 + i)
		fpB[i] = byte(i)
	}
	const session = "v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\n"
	const media = "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n"

	tests := []struct {
		name    string
		sdp     string
		want    []byte
		wantErr bool
	}{
		{
			name: "pion style uppercase at media level",
			sdp:  session + media + "a=fingerprint:sha-256 " + strings.ToUpper(colonHex(fpA)) + "\r\na=setup:actpass\r\n",
			want: fpA,
		},
		{
			name: "lowercase hex with uppercase algorithm",
			sdp:  session + media + "a=fingerprint:SHA-256 " + colonHex(fpA) + "\r\n",
			want: fpA,
		},
		{
			name: "session level line wins over a later media level line",
			sdp:  session + "a=fingerprint:sha-256 " + colonHex(fpB) + "\r\n" + media + "a=fingerprint:sha-256 " + colonHex(fpA) + "\r\n",
			want: fpB,
		},
		{
			// This parser rule alone is not the security boundary: Pion's DTLS
			// validates the certificate against a single fingerprint line of
			// any algorithm (here the first media-level one), so a genuine
			// sha-1 line can precede an arbitrary sha-256 one. The cross-check
			// against the negotiated certificates in sendAuthChallenge
			// (verifyDTLSFingerprints) is what rejects that.
			name: "sha-1 line before sha-256 line is skipped",
			sdp:  session + media + "a=fingerprint:sha-1 " + colonHex(fpA[:20]) + "\r\na=fingerprint:sha-256 " + colonHex(fpB) + "\r\n",
			want: fpB,
		},
		{
			name: "bare LF line endings",
			sdp:  "v=0\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\na=fingerprint:sha-256 " + colonHex(fpA) + "\n",
			want: fpA,
		},
		{
			name:    "missing fingerprint line",
			sdp:     session + media + "a=setup:actpass\r\n",
			wantErr: true,
		},
		{
			name:    "only a sha-1 fingerprint",
			sdp:     session + media + "a=fingerprint:sha-1 " + colonHex(fpA[:20]) + "\r\n",
			wantErr: true,
		},
		{
			name:    "sha-256 fingerprint too short",
			sdp:     session + media + "a=fingerprint:sha-256 " + colonHex(fpA[:31]) + "\r\n",
			wantErr: true,
		},
		{
			name:    "sha-256 fingerprint too long",
			sdp:     session + media + "a=fingerprint:sha-256 " + colonHex(append(append([]byte{}, fpA...), 0xFF)) + "\r\n",
			wantErr: true,
		},
		{
			name:    "bad hex",
			sdp:     session + media + "a=fingerprint:sha-256 ZZ" + colonHex(fpA)[2:] + "\r\n",
			wantErr: true,
		},
		{
			name:    "misplaced colon separators",
			sdp:     session + media + "a=fingerprint:sha-256 0" + colonHex(fpA)[:94] + "\r\n",
			wantErr: true,
		},
		{
			name:    "colon in an octet position",
			sdp:     session + media + "a=fingerprint:sha-256 :" + colonHex(fpA)[1:] + "\r\n",
			wantErr: true,
		},
		{
			name:    "hex without colon separators",
			sdp:     session + media + "a=fingerprint:sha-256 " + hex.EncodeToString(fpA) + "\r\n",
			wantErr: true,
		},
		{
			name:    "missing value",
			sdp:     session + media + "a=fingerprint:sha-256\r\n",
			wantErr: true,
		},
		{
			// Fail closed: a malformed first sha-256 line is not skipped in
			// favour of a later valid one.
			name:    "malformed first sha-256 line before a valid one",
			sdp:     session + "a=fingerprint:sha-256 " + colonHex(fpB[:31]) + "\r\n" + media + "a=fingerprint:sha-256 " + colonHex(fpA) + "\r\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sdpSHA256Fingerprint(tt.sdp)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got fingerprint %x", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("fingerprint = %x, want %x", got, tt.want)
			}
		})
	}
}

// TestHostProofMAC_KnownAnswer pins the host proof layout with a known-answer
// vector the mobile test suite reuses to stay bit-for-bit compatible:
//
//	secret      = 32 x 0x42
//	nonce       = 32 x 0x01
//	responseMAC = 32 x 0x02
//	offerFP     = 32 x 0x03
//	answerFP    = 32 x 0x04
//	mac = HMAC-SHA256(secret, "pmux-host-proof-v1" || nonce || responseMAC || offerFP || answerFP)
//	    = cdc27769ae6711f0cb07b51cf4170c978810c9e8ca1f4442d7aa6cbfd7d0253a (hex)
//
// The expected value was computed independently (Python hmac/hashlib).
func TestHostProofMAC_KnownAnswer(t *testing.T) {
	const wantHex = "cdc27769ae6711f0cb07b51cf4170c978810c9e8ca1f4442d7aa6cbfd7d0253a"
	secret := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x01}, 32)
	responseMAC := bytes.Repeat([]byte{0x02}, 32)
	offerFP := bytes.Repeat([]byte{0x03}, 32)
	answerFP := bytes.Repeat([]byte{0x04}, 32)

	got := hostProofMAC(secret, nonce, responseMAC, offerFP, answerFP)
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("hostProofMAC = %x, want %s", got, wantHex)
	}

	// The same value from a single write of the concatenated input, so a
	// layout drift in hostProofMAC can't hide behind a regenerated vector.
	input := append([]byte("pmux-host-proof-v1"), nonce...)
	input = append(input, responseMAC...)
	input = append(input, offerFP...)
	input = append(input, answerFP...)
	m := hmac.New(sha256.New, secret)
	m.Write(input)
	if !hmac.Equal(got, m.Sum(nil)) {
		t.Fatal("hostProofMAC does not match HMAC over the plain concatenated input")
	}

	// Domain separation: the host proof must never equal the mobile's
	// auth_response MAC over the same nonce.
	respMAC, _ := base64.StdEncoding.DecodeString(authMAC(secret, nonce))
	if hmac.Equal(got, respMAC) {
		t.Fatal("host proof must differ from authMAC(secret, nonce)")
	}
}

// TestPeer_VerifyAuthResponse_ProofSendFailureClosesPeer covers the peer
// without a DataChannel: its response verifies, but because the proof can't be
// sent the mobile would never treat the connection as usable, so auth resolves
// as a failure and the peer is closed. The peer is never authenticated, not even
// transiently, because the proof is sent before the outcome is committed.
func TestPeer_VerifyAuthResponse_ProofSendFailureClosesPeer(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	p := newAuthTestPeer(nonce)

	p.verifyAuthResponse(&protocol.AuthResponseRequest{
		Type: "auth_response",
		Mac:  authMAC(testSharedSecret, nonce),
	})

	// Resolved synchronously, before the asynchronous close, so no inbound
	// message in that window is dispatched or answered.
	p.mu.Lock()
	resolved, authed := p.authResolved, p.authenticated
	cleared := p.authOfferFP == nil && p.authAnswerFP == nil && p.authNonce == nil
	p.mu.Unlock()
	if !resolved || authed {
		t.Fatalf("authResolved=%v authenticated=%v, want resolved and not authenticated", resolved, authed)
	}
	if !cleared {
		t.Fatal("nonce and fingerprints must be cleared once auth fails")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		t.Fatal("peer must be closed when the auth proof cannot be sent")
	}
}

// TestPeer_SendAuthChallenge_FailsWithoutFingerprints verifies the challenge is
// never armed when the SDP fingerprints can't be read, so the peer can never
// authenticate (fail closed).
func TestPeer_SendAuthChallenge_FailsWithoutFingerprints(t *testing.T) {
	pc, err := fastAPI(t).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create peer connection: %v", err)
	}
	p := &Peer{
		DeviceID:     "mobile-nofp",
		conn:         pc, // no local or remote description set
		logger:       testLogger(),
		sharedSecret: testSharedSecret,
		sendReady:    make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
	defer p.Close()

	p.sendAuthChallenge()

	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.authResolved || p.authenticated {
		t.Fatalf("authResolved=%v authenticated=%v, want resolved and not authenticated", p.authResolved, p.authenticated)
	}
	if p.authNonce != nil || p.authTimer != nil {
		t.Fatal("no challenge must be armed when the fingerprints are unavailable")
	}
}

// loopbackAuthPeer is an agent Peer wired to a real DataChannel whose far end
// (the answerer) records every decoded message the agent sends. No handlers
// are installed on the agent side, so tests drive the auth methods directly.
type loopbackAuthPeer struct {
	peer     *Peer
	answerer *webrtc.PeerConnection
	received chan protocol.Message
}

func newLoopbackAuthPeer(t *testing.T) *loopbackAuthPeer {
	t.Helper()
	return newLoopbackAuthPeerWith(t, webrtc.Configuration{}, nil)
}

// newLoopbackAuthPeerWith is newLoopbackAuthPeer with the answerer built from
// answererConfig and, if rewriteAnswer is non-nil, the answer SDP rewritten
// before the agent applies it (as a signaling attacker could).
func newLoopbackAuthPeerWith(t *testing.T, answererConfig webrtc.Configuration, rewriteAnswer func(sdp string) string) *loopbackAuthPeer {
	t.Helper()
	api := fastAPI(t)

	offerer, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatalf("create offerer: %v", err)
	}
	answerer, err := api.NewPeerConnection(answererConfig)
	if err != nil {
		offerer.Close()
		t.Fatalf("create answerer: %v", err)
	}

	received := make(chan protocol.Message, 16)
	answerer.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnMessage(func(msg webrtc.DataChannelMessage) {
			if decoded, err := protocol.Decode(msg.Data); err == nil {
				received <- decoded
			}
		})
	})

	dc, err := offerer.CreateDataChannel(DataChannelLabel, nil)
	if err != nil {
		t.Fatalf("create data channel: %v", err)
	}
	opened := make(chan struct{})
	dc.OnOpen(func() { close(opened) })

	offer, err := offerer.CreateOffer(nil)
	if err != nil {
		t.Fatalf("create offer: %v", err)
	}
	offerGatherDone := webrtc.GatheringCompletePromise(offerer)
	if err := offerer.SetLocalDescription(offer); err != nil {
		t.Fatalf("set offerer local description: %v", err)
	}
	<-offerGatherDone
	if err := answerer.SetRemoteDescription(*offerer.LocalDescription()); err != nil {
		t.Fatalf("set answerer remote description: %v", err)
	}
	answer, err := answerer.CreateAnswer(nil)
	if err != nil {
		t.Fatalf("create answer: %v", err)
	}
	answerGatherDone := webrtc.GatheringCompletePromise(answerer)
	if err := answerer.SetLocalDescription(answer); err != nil {
		t.Fatalf("set answerer local description: %v", err)
	}
	<-answerGatherDone
	answerSDP := answerer.LocalDescription().SDP
	if rewriteAnswer != nil {
		answerSDP = rewriteAnswer(answerSDP)
	}
	if err := offerer.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answerSDP}); err != nil {
		t.Fatalf("set offerer remote description: %v", err)
	}

	select {
	case <-opened:
	case <-time.After(15 * time.Second):
		t.Fatal("DataChannel did not open within 15s")
	}

	p := &Peer{
		DeviceID:     "mobile-loopback",
		conn:         offerer,
		dc:           dc,
		logger:       testLogger(),
		sharedSecret: testSharedSecret,
		sendReady:    make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
	t.Cleanup(func() {
		p.Close()
		answerer.Close()
	})
	return &loopbackAuthPeer{peer: p, answerer: answerer, received: received}
}

// challenge runs sendAuthChallenge and returns the raw nonce the answerer got.
func (l *loopbackAuthPeer) challenge(t *testing.T) []byte {
	t.Helper()
	l.peer.sendAuthChallenge()
	select {
	case msg := <-l.received:
		ch, ok := msg.(*protocol.AuthChallengeEvent)
		if !ok {
			t.Fatalf("first message = %s, want auth_challenge", msg.MessageType())
		}
		nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
		if err != nil {
			t.Fatalf("decode challenge nonce: %v", err)
		}
		return nonce
	case <-time.After(5 * time.Second):
		t.Fatal("no auth_challenge received")
	}
	return nil
}

// expectNoAuthProof fails if an auth_proof reaches the answerer within a short
// window.
func (l *loopbackAuthPeer) expectNoAuthProof(t *testing.T) {
	t.Helper()
	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case msg := <-l.received:
			if _, ok := msg.(*protocol.AuthProofEvent); ok {
				t.Fatal("auth_proof must not be sent")
			}
		case <-deadline:
			return
		}
	}
}

func TestPeer_AuthHandshake_SendsOneValidProof(t *testing.T) {
	l := newLoopbackAuthPeer(t)
	nonce := l.challenge(t)

	respB64 := authMAC(testSharedSecret, nonce)
	l.peer.verifyAuthResponse(&protocol.AuthResponseRequest{Type: "auth_response", Mac: respB64})

	var proof *protocol.AuthProofEvent
	select {
	case msg := <-l.received:
		var ok bool
		if proof, ok = msg.(*protocol.AuthProofEvent); !ok {
			t.Fatalf("message after auth_response = %s, want auth_proof", msg.MessageType())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no auth_proof received after a valid auth_response")
	}

	// Verify as the mobile would: fingerprints from its own descriptions
	// (offer = remote, answer = local) and the raw response MAC it sent.
	offerFP, err := sdpSHA256Fingerprint(l.answerer.RemoteDescription().SDP)
	if err != nil {
		t.Fatalf("parse offer fingerprint: %v", err)
	}
	answerFP, err := sdpSHA256Fingerprint(l.answerer.LocalDescription().SDP)
	if err != nil {
		t.Fatalf("parse answer fingerprint: %v", err)
	}
	respMAC, _ := base64.StdEncoding.DecodeString(respB64)
	gotMAC, err := base64.StdEncoding.DecodeString(proof.Mac)
	if err != nil {
		t.Fatalf("auth_proof MAC not valid base64: %v", err)
	}
	if !hmac.Equal(gotMAC, hostProofMAC(testSharedSecret, nonce, respMAC, offerFP, answerFP)) {
		t.Fatal("auth_proof MAC does not verify")
	}

	// Exactly one proof.
	l.expectNoAuthProof(t)
}

func TestPeer_AuthProofNotSentOnFailure(t *testing.T) {
	tests := []struct {
		name string
		act  func(p *Peer, nonce []byte)
	}{
		{
			name: "bad MAC",
			act: func(p *Peer, nonce []byte) {
				p.verifyAuthResponse(&protocol.AuthResponseRequest{
					Type: "auth_response",
					Mac:  authMAC([]byte("not-the-shared-secret"), nonce),
				})
			},
		},
		{
			name: "wrong message type",
			act: func(p *Peer, nonce []byte) {
				p.verifyAuthResponse(&protocol.PingRequest{Type: "ping"})
			},
		},
		{
			// The timeout resolves auth first; a valid response arriving
			// afterwards must not produce a proof.
			name: "timeout",
			act: func(p *Peer, nonce []byte) {
				p.failAuth("authentication timeout")
				p.verifyAuthResponse(&protocol.AuthResponseRequest{
					Type: "auth_response",
					Mac:  authMAC(testSharedSecret, nonce),
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := newLoopbackAuthPeer(t)
			nonce := l.challenge(t)
			tt.act(l.peer, nonce)
			l.expectNoAuthProof(t)

			l.peer.mu.Lock()
			authed := l.peer.authenticated
			l.peer.mu.Unlock()
			if authed {
				t.Fatal("peer must not be authenticated")
			}
		})
	}
}

// TestPeer_SendAuthChallenge_RejectsFingerprintNotVerifiedByDTLS reproduces a
// signaling attacker rewriting the answer: a genuine sha-1 fingerprint of the
// answerer's certificate followed by an arbitrary sha-256 one. Pion's DTLS
// accepts the certificate via the sha-1 line, while the SDP parser binds the
// arbitrary sha-256 value, so the agent must refuse to run the handshake.
func TestPeer_SendAuthChallenge_RejectsFingerprintNotVerifiedByDTLS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert, err := webrtc.GenerateCertificate(key)
	if err != nil {
		t.Fatalf("generate certificate: %v", err)
	}
	certPEM, err := cert.PEM()
	if err != nil {
		t.Fatalf("encode certificate: %v", err)
	}
	var der []byte
	for rest := []byte(certPEM); ; {
		var block *pem.Block
		if block, rest = pem.Decode(rest); block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			der = block.Bytes
		}
	}
	if der == nil {
		t.Fatal("no CERTIFICATE block in the generated certificate PEM")
	}
	realSHA1 := sha1.Sum(der)
	bogusSHA256 := bytes.Repeat([]byte{0xEE}, sha256.Size)

	rewrite := func(sdp string) string {
		var out []string
		for _, line := range strings.Split(sdp, "\r\n") {
			if strings.HasPrefix(line, "a=fingerprint:sha-256") {
				out = append(out,
					"a=fingerprint:sha-1 "+strings.ToUpper(colonHex(realSHA1[:])),
					"a=fingerprint:sha-256 "+colonHex(bogusSHA256))
				continue
			}
			out = append(out, line)
		}
		return strings.Join(out, "\r\n")
	}

	// The helper waits for the DataChannel to open, so DTLS accepted the
	// rewritten answer.
	l := newLoopbackAuthPeerWith(t, webrtc.Configuration{Certificates: []webrtc.Certificate{*cert}}, rewrite)
	p := l.peer

	bound, err := sdpSHA256Fingerprint(p.conn.RemoteDescription().SDP)
	if err != nil {
		t.Fatalf("parse rewritten answer fingerprint: %v", err)
	}
	if !bytes.Equal(bound, bogusSHA256) {
		t.Fatalf("parser bound %x, want the arbitrary sha-256 value", bound)
	}

	p.sendAuthChallenge()

	p.mu.Lock()
	resolved, authed := p.authResolved, p.authenticated
	armed := p.authNonce != nil || p.authTimer != nil
	p.mu.Unlock()
	if !resolved || authed {
		t.Fatalf("authResolved=%v authenticated=%v, want resolved and not authenticated", resolved, authed)
	}
	if armed {
		t.Fatal("no challenge must be armed when the fingerprints don't match DTLS")
	}

	// Nothing at all reaches the answerer: no challenge, so never a proof.
	select {
	case msg := <-l.received:
		t.Fatalf("agent sent %s, want nothing", msg.MessageType())
	case <-time.After(500 * time.Millisecond):
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("peer must be closed when the fingerprints don't match DTLS")
}

func TestPeer_VerifyDTLSFingerprints(t *testing.T) {
	l := newLoopbackAuthPeer(t)
	offerFP, answerFP, err := l.peer.sdpFingerprints()
	if err != nil {
		t.Fatalf("read SDP fingerprints: %v", err)
	}
	bogus := bytes.Repeat([]byte{0xEE}, sha256.Size)

	tests := []struct {
		name     string
		offerFP  []byte
		answerFP []byte
		wantErr  bool
	}{
		{name: "honest descriptions match DTLS", offerFP: offerFP, answerFP: answerFP},
		{name: "answer fingerprint not the remote certificate", offerFP: offerFP, answerFP: bogus, wantErr: true},
		{name: "offer fingerprint not the local certificate", offerFP: bogus, answerFP: answerFP, wantErr: true},
		{name: "fingerprints swapped", offerFP: answerFP, answerFP: offerFP, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := l.peer.verifyDTLSFingerprints(tt.offerFP, tt.answerFP)
			if tt.wantErr && err == nil {
				t.Fatal("expected a fingerprint mismatch error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
