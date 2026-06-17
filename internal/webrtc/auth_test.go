package webrtc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/protocol"
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
		sendReady:    make(chan struct{}, 1),
		done:         make(chan struct{}),
	}
}

func TestPeer_VerifyAuthResponse_ValidMACAuthenticates(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	p := newAuthTestPeer(nonce)

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
		if m.TargetDeviceID == "mobile-nosecret" {
			rejected = true
		}
	}
	if !rejected {
		t.Error("expected connection_rejected sent to the device")
	}

	pm.CloseAll()
}
