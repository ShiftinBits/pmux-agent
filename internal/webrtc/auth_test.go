package webrtc

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
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
// not be marked confirmed and must be torn down, since failAuth no longer
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
	if !p.authenticated {
		t.Error("peer with a valid response should be authenticated")
	}
	if p.authConfirmed {
		t.Error("authConfirmed must stay false when auth_confirm was not sent")
	}
}

func TestPeer_FailAuthNoOpAfterSuccess(t *testing.T) {
	useFakeDTLSFingerprints(t, testHostFp, testMobileFp, nil)
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

	// The timeout resolves auth first.
	p.failAuth("authentication timeout")

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
		if m.TargetDeviceID == "mobile-nosecret" {
			rejected = true
		}
	}
	if !rejected {
		t.Error("expected connection_rejected sent to the device")
	}

	pm.CloseAll()
}
