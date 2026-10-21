package agent

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"

	"github.com/shiftinbits/pmux-agent/internal/auth"
	"github.com/shiftinbits/pmux-agent/internal/config"
)

func TestRunPair_NoIdentity(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()

	var out bytes.Buffer
	in := strings.NewReader("")

	err := RunPair(paths, cfg, store, "", in, &out)
	if err == nil {
		t.Fatal("expected error when no identity exists")
	}
	if !strings.Contains(err.Error(), "no identity found") {
		t.Errorf("expected 'no identity found' error, got: %v", err)
	}
}

func TestRunPair_ExistingPairing_UserDeclines(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()

	// Generate identity so HasIdentity passes
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// Write an existing paired device
	err := auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID: "abc123def456abc123def456abc123de",
		Name:     "Test Phone",
		PairedAt: time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}

	var out bytes.Buffer
	in := strings.NewReader("n\n")

	if err := RunPair(paths, cfg, store, "", in, &out); err != nil {
		t.Fatalf("RunPair should return nil on decline, got: %v", err)
	}

	output := out.String()
	if !strings.Contains(output, "Test Phone") {
		t.Errorf("expected device name in prompt, got: %s", output)
	}
	if !strings.Contains(output, "Replace it?") {
		t.Errorf("expected 'Replace it?' prompt, got: %s", output)
	}
	if !strings.Contains(output, "Pairing cancelled.") {
		t.Errorf("expected 'Pairing cancelled.' message, got: %s", output)
	}

	// Verify device was NOT removed
	device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device == nil {
		t.Error("device should NOT have been removed")
	}
}

func TestRunPair_ExistingPairing_EOFDeclines(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	cfg := config.Defaults()

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	err := auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID: "abc123def456abc123def456abc123de",
		Name:     "Test Phone",
		PairedAt: time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}

	var out bytes.Buffer
	in := strings.NewReader("") // EOF

	if err := RunPair(paths, cfg, store, "", in, &out); err != nil {
		t.Fatalf("RunPair should return nil on EOF, got: %v", err)
	}

	if !strings.Contains(out.String(), "Pairing cancelled.") {
		t.Errorf("expected 'Pairing cancelled.' on EOF, got: %s", out.String())
	}
}

func TestCheckServerTransport(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://signal.pmux.io", false},
		{"wss://signal.example.com", false},
		{"http://localhost:8787", false},
		{"http://127.0.0.1:1", false},
		{"http://127.0.0.2:8787", false},
		{"http://[::ffff:127.0.0.1]:8787", false},
		{"ws://[::1]:8787", false},
		{"http://10.0.0.5:8787", false},
		{"http://172.16.0.1", false},
		{"http://172.31.255.255/path", false},
		{"http://192.168.1.10:8787", false},
		{"http://example.com", true},
		{"ws://example.com", true},
		{"http://172.32.0.1", true},
		{"http://172.15.0.1", true},
		{"http://8.8.8.8", true},
		{"http://[fd00::1]:8787", true},
		{"http://localhost.example.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := checkServerTransport(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkServerTransport(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestRunPair_RefusesHTTP_NonLocalServer(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// An existing pairing must survive the refusal: the check runs before
	// the replace prompt.
	err := auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID: "abc123def456abc123def456abc123de",
		Name:     "Test Phone",
		PairedAt: time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}

	for _, serverURL := range []string{"http://example.com", "ws://example.com:8787"} {
		t.Run(serverURL, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Server.URL = serverURL

			var out bytes.Buffer
			in := strings.NewReader("y\n")

			err := RunPair(paths, cfg, store, "", in, &out)
			if err == nil {
				t.Fatal("expected refusal for unencrypted non-local server")
			}
			if !strings.Contains(err.Error(), "refusing to pair over unencrypted") {
				t.Errorf("expected refusal error, got: %v", err)
			}
			if strings.Contains(out.String(), "Contacting signaling server") {
				t.Errorf("server should not be contacted, got output: %s", out.String())
			}
			if strings.Contains(out.String(), "Replace it?") {
				t.Errorf("refusal should precede the replace prompt, got output: %s", out.String())
			}

			device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
			if err != nil {
				t.Fatalf("LoadPairedDevice: %v", err)
			}
			if device == nil {
				t.Error("existing pairing should not be removed on refusal")
			}
		})
	}
}

func TestRunPair_NoRefusal_LocalOrHTTPS(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// Port 1 refuses connections, so each case errors at InitiatePairing,
	// after the transport check has passed.
	for _, serverURL := range []string{"http://localhost:1", "http://127.0.0.1:1", "https://127.0.0.1:1"} {
		t.Run(serverURL, func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Server.URL = serverURL

			var out bytes.Buffer
			in := strings.NewReader("")

			err := RunPair(paths, cfg, store, "", in, &out)
			if err == nil {
				t.Fatal("expected error from unreachable server")
			}
			if strings.Contains(err.Error(), "refusing") {
				t.Errorf("expected no refusal for %s, got: %v", serverURL, err)
			}
			if !strings.Contains(err.Error(), "failed to initiate pairing") {
				t.Errorf("expected 'failed to initiate pairing' error, got: %v", err)
			}
		})
	}
}

// fakePairConfig configures newFakePairServer.
type fakePairConfig struct {
	// pairComplete builds the mobile's pair_complete from the host's X25519
	// public key and device ID.
	pairComplete func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage
	// legacy emulates a server without confirmed pairing: it doesn't echo
	// pairConfirm, answers pair_accept/pair_reject with an error frame and
	// serves DELETE /v1/auth/pairing.
	legacy bool
	// commitFails makes the pair_result for a pair_accept carry ok:false.
	commitFails bool
	// pairCompleteFirst sends pair_complete before the auth reply.
	pairCompleteFirst bool
}

// fakePairServer emulates the signaling server endpoints used by RunPair and
// plays the mobile: once the host has initiated pairing, the WebSocket
// delivers a pair_complete built from the host's X25519 public key and
// device ID, then records the host's answers. Any other request fails the
// test.
type fakePairServer struct {
	*httptest.Server

	mu          sync.Mutex
	hostPub     []byte
	hostDevice  string
	pairConfirm bool

	// deletes counts DELETE /v1/auth/pairing requests (legacy only).
	deletes atomic.Int32
	// frames receives, when the WebSocket handler returns, the types of the
	// frames the host sent after pair_complete, presence excluded.
	frames chan []string
}

// hostFrames waits for the WebSocket exchange to finish and returns the
// types of the host's frames after pair_complete.
func (fs *fakePairServer) hostFrames(t *testing.T) []string {
	t.Helper()
	select {
	case frames := <-fs.frames:
		return frames
	case <-time.After(5 * time.Second):
		t.Fatal("WebSocket exchange did not finish")
		return nil
	}
}

func newFakePairServer(t *testing.T, cfg fakePairConfig) *fakePairServer {
	t.Helper()
	fs := &fakePairServer{frames: make(chan []string, 1)}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.NotFound(w, r)
	})
	mux.HandleFunc("POST /v1/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"nonce":"test-nonce"}`)
	})
	mux.HandleFunc("POST /v1/auth/pair/initiate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			DeviceID     string `json:"deviceId"`
			X25519PubKey string `json:"x25519PublicKey"`
			PairConfirm  bool   `json:"pairConfirm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		pub, err := base64.StdEncoding.DecodeString(req.X25519PubKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fs.mu.Lock()
		fs.hostPub = pub
		fs.hostDevice = req.DeviceID
		fs.pairConfirm = req.PairConfirm
		fs.mu.Unlock()
		if req.PairConfirm && !cfg.legacy {
			fmt.Fprint(w, `{"pairingCode":"ABC234","pairConfirm":true}`)
			return
		}
		fmt.Fprint(w, `{"pairingCode":"ABC234"}`)
	})
	mux.HandleFunc("POST /v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"token":"test-jwt"}`)
	})
	if cfg.legacy {
		mux.HandleFunc("DELETE /v1/auth/pairing", func(w http.ResponseWriter, r *http.Request) {
			fs.deletes.Add(1)
		})
	}
	mux.HandleFunc("GET /v1/ws", func(w http.ResponseWriter, r *http.Request) {
		var frames []string
		defer func() {
			select {
			case fs.frames <- frames:
			default:
			}
		}()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		if _, _, err := conn.ReadMessage(); err != nil { // auth
			return
		}
		fs.mu.Lock()
		msg := cfg.pairComplete(fs.hostPub, fs.hostDevice)
		fs.mu.Unlock()
		pairComplete, err := json.Marshal(msg)
		if err != nil {
			return
		}
		replies := [][]byte{[]byte(`{"type":"auth","status":"ok"}`), pairComplete}
		if cfg.pairCompleteFirst {
			replies[0], replies[1] = replies[1], replies[0]
		}
		for _, reply := range replies {
			if err := conn.WriteMessage(websocket.TextMessage, reply); err != nil {
				return
			}
		}

		for { // record the host's frames until it hangs up
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var frame struct {
				Type           string `json:"type"`
				MobileDeviceID string `json:"mobileDeviceId"`
			}
			if err := json.Unmarshal(data, &frame); err != nil {
				frames = append(frames, string(data))
				continue
			}
			if frame.Type == "presence" {
				continue
			}
			frames = append(frames, frame.Type)
			var answer string
			switch {
			case cfg.legacy:
				answer = fmt.Sprintf(`{"type":"error","error":"Unknown message type: %s"}`, frame.Type)
			case frame.Type == "pair_accept":
				answer = fmt.Sprintf(`{"type":"pair_result","mobileDeviceId":%q,"ok":%t}`, frame.MobileDeviceID, !cfg.commitFails)
			default:
				continue
			}
			conn.WriteMessage(websocket.TextMessage, []byte(answer)) //nolint:errcheck // client reports read failures
		}
	})

	fs.Server = httptest.NewServer(mux)
	t.Cleanup(fs.Close)
	return fs
}

// pairBindForTest builds BIND = hostPub || mobilePub || hostDeviceID ||
// mobileDeviceID independently of the auth package.
func pairBindForTest(hostPub, mobilePub []byte, hostDeviceID, mobileDeviceID string) []byte {
	bind := append([]byte{}, hostPub...)
	bind = append(bind, mobilePub...)
	bind = append(bind, hostDeviceID...)
	return append(bind, mobileDeviceID...)
}

// pairMacForTest computes the pair_complete MAC the way the mobile does:
// HMAC-SHA256(secret, "pocketmux-pair-mac-v2" || mobilePub || mobileDeviceID).
func pairMacForTest(secret string, mobilePub []byte, mobileDeviceID string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("pocketmux-pair-mac-v2"))
	h.Write(mobilePub)
	h.Write([]byte(mobileDeviceID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// assertFrames checks the host's frames after pair_complete are exactly want.
func assertFrames(t *testing.T, srv *fakePairServer, want ...string) {
	t.Helper()
	got := srv.hostFrames(t)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("host frames after pair_complete = %q, want %q", got, want)
	}
}

func TestRunPair_PairCompleteMAC(t *testing.T) {
	const (
		testSecret     = "ABCDEFGHJKLMNPQR"
		mobileDeviceID = "fedcba9876543210fedcba9876543210"
	)

	mobilePriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate mobile key: %v", err)
	}
	mobilePub := mobilePriv.PublicKey().Bytes()
	mobilePubB64 := base64.StdEncoding.EncodeToString(mobilePub)

	attackerPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	attackerPubB64 := base64.StdEncoding.EncodeToString(attackerPriv.PublicKey().Bytes())

	// A low-order X25519 point passes the MAC check but fails ECDH.
	lowOrderPub := make([]byte, 32)

	tests := []struct {
		name         string
		pairComplete func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage
		wantErr      error  // checked with errors.Is when set
		wantErrText  string // checked with strings.Contains when set
	}{
		{
			name: "valid pairMac saves device",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        mobileDeviceID,
					MobileX25519PublicKey: mobilePubB64,
					MobileName:            "Test Phone",
					PairMac:               pairMacForTest(testSecret, mobilePub, mobileDeviceID),
				}
			},
		},
		{
			name: "pairMac with wrong secret aborts",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        mobileDeviceID,
					MobileX25519PublicKey: mobilePubB64,
					PairMac:               pairMacForTest("ZZZZZZZZZZZZZZZZ", mobilePub, mobileDeviceID),
				}
			},
			wantErr: errPairMACRejected,
		},
		{
			name: "substituted mobile key aborts",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        mobileDeviceID,
					MobileX25519PublicKey: attackerPubB64,
					PairMac:               pairMacForTest(testSecret, mobilePub, mobileDeviceID),
				}
			},
			wantErr: errPairMACRejected,
		},
		{
			name: "missing pairMac aborts",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        mobileDeviceID,
					MobileX25519PublicKey: mobilePubB64,
				}
			},
			wantErr: errPairMACRejected,
		},
		{
			name: "low-order mobile key aborts",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        mobileDeviceID,
					MobileX25519PublicKey: base64.StdEncoding.EncodeToString(lowOrderPub),
					PairMac:               pairMacForTest(testSecret, lowOrderPub, mobileDeviceID),
				}
			},
			wantErrText: "key exchange failed",
		},
		{
			name: "invalid mobile device ID aborts",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        "NOT-A-VALID-ID",
					MobileX25519PublicKey: mobilePubB64,
					PairMac:               pairMacForTest(testSecret, mobilePub, "NOT-A-VALID-ID"),
				}
			},
			wantErrText: "invalid device ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := testPaths(t)
			store := auth.NewMemorySecretStore()
			id, err := auth.GenerateIdentity(paths.KeysDir, store)
			if err != nil {
				t.Fatalf("GenerateIdentity: %v", err)
			}

			restarted := stubPairSeams(t, testSecret)

			srv := newFakePairServer(t, fakePairConfig{pairComplete: tt.pairComplete})
			cfg := config.Defaults()
			cfg.Server.URL = srv.URL

			var out bytes.Buffer
			err = RunPair(paths, cfg, store, "", strings.NewReader(""), &out)

			if !strings.Contains(out.String(), "Manual pairing code: ABC234-ABCD-EFGH-JKLM-NPQR") {
				t.Errorf("expected manual code with secret in output, got: %s", out.String())
			}
			if strings.Contains(out.String(), legacyWarning) {
				t.Errorf("a confirming server should not trigger the legacy-server warning, got: %s", out.String())
			}
			if !restarted.Load() {
				t.Error("agent stopped for pairing should be restarted")
			}

			device, loadErr := auth.LoadPairedDevice(paths.PairedDevices, store)
			if loadErr != nil {
				t.Fatalf("LoadPairedDevice: %v", loadErr)
			}

			srv.mu.Lock()
			pairConfirm := srv.pairConfirm
			srv.mu.Unlock()
			if !pairConfirm {
				t.Error("pair initiate should request confirmed pairing")
			}

			if tt.wantErr != nil || tt.wantErrText != "" {
				if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
					t.Errorf("RunPair error = %v, want %v", err, tt.wantErr)
				}
				if err == nil || !strings.Contains(err.Error(), tt.wantErrText) {
					t.Errorf("RunPair error = %v, want it to contain %q", err, tt.wantErrText)
				}
				if device != nil {
					t.Errorf("no device should be saved, got %+v", device)
				}
				assertFrames(t, srv, "pair_reject")
				return
			}

			if err != nil {
				t.Fatalf("RunPair: %v", err)
			}
			assertFrames(t, srv, "pair_accept")
			if device == nil {
				t.Fatal("expected paired device to be saved")
			}
			if device.DeviceID != mobileDeviceID {
				t.Errorf("DeviceID = %q, want %q", device.DeviceID, mobileDeviceID)
			}
			if device.Name != "Test Phone" {
				t.Errorf("Name = %q, want %q", device.Name, "Test Phone")
			}

			// The mobile derives the same secret from its own private key.
			srv.mu.Lock()
			hostPubBytes := srv.hostPub
			srv.mu.Unlock()
			hostPub, err := ecdh.X25519().NewPublicKey(hostPubBytes)
			if err != nil {
				t.Fatalf("parse host key: %v", err)
			}
			raw, err := mobilePriv.ECDH(hostPub)
			if err != nil {
				t.Fatalf("mobile ECDH: %v", err)
			}
			info := append([]byte("pocketmux-pairing-v2"), pairBindForTest(hostPubBytes, mobilePub, id.DeviceID, mobileDeviceID)...)
			want := make([]byte, 32)
			if _, err := io.ReadFull(hkdf.New(sha256.New, raw, []byte(testSecret), info), want); err != nil {
				t.Fatalf("HKDF: %v", err)
			}
			if device.SharedSecret != base64.StdEncoding.EncodeToString(want) {
				t.Error("stored shared secret does not match the mobile-side derivation")
			}
		})
	}
}

// stubPairSeams makes RunPair use secret as the pairing secret and record
// agent restarts instead of spawning an agent.
func stubPairSeams(t *testing.T, secret string) *atomic.Bool {
	t.Helper()
	origSecret, origEnsure := generatePairingSecret, ensureAgentRunning
	t.Cleanup(func() { generatePairingSecret, ensureAgentRunning = origSecret, origEnsure })
	generatePairingSecret = func() (string, error) { return secret, nil }
	var restarted atomic.Bool
	ensureAgentRunning = func(config.Paths, auth.SecretStore) error {
		restarted.Store(true)
		return nil
	}
	return &restarted
}

// pairCompleteFromNewMobile returns a pair_complete builder for a fresh
// mobile X25519 key, with a pairMac keyed by secret.
func pairCompleteFromNewMobile(t *testing.T, secret, mobileDeviceID string) func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
	t.Helper()
	mobilePriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate mobile key: %v", err)
	}
	mobilePub := mobilePriv.PublicKey().Bytes()
	return func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
		return auth.PairCompleteMessage{
			Type:                  "pair_complete",
			MobileDeviceID:        mobileDeviceID,
			MobileX25519PublicKey: base64.StdEncoding.EncodeToString(mobilePub),
			MobileName:            "New Phone",
			PairMac:               pairMacForTest(secret, mobilePub, mobileDeviceID),
		}
	}
}

// newPairHost generates an identity in fresh paths and memory store and
// stubs RunPair's seams with testSecret.
func newPairHost(t *testing.T, testSecret string) (config.Paths, *auth.MemorySecretStore) {
	t.Helper()
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	stubPairSeams(t, testSecret)
	return paths, store
}

func TestRunPair_PairCompleteBeforeAuthReply(t *testing.T) {
	const (
		testSecret     = "ABCDEFGHJKLMNPQR"
		mobileDeviceID = "fedcba9876543210fedcba9876543210"
	)
	paths, store := newPairHost(t, testSecret)

	srv := newFakePairServer(t, fakePairConfig{
		pairComplete:      pairCompleteFromNewMobile(t, testSecret, mobileDeviceID),
		pairCompleteFirst: true,
	})
	cfg := config.Defaults()
	cfg.Server.URL = srv.URL

	var out bytes.Buffer
	if err := RunPair(paths, cfg, store, "", strings.NewReader(""), &out); err != nil {
		t.Fatalf("RunPair: %v", err)
	}
	assertFrames(t, srv, "pair_accept")

	device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device == nil || device.DeviceID != mobileDeviceID {
		t.Fatalf("paired device = %+v, want %s", device, mobileDeviceID)
	}
}

func TestRunPair_ServerRejectsCommit(t *testing.T) {
	const (
		testSecret     = "ABCDEFGHJKLMNPQR"
		mobileDeviceID = "fedcba9876543210fedcba9876543210"
	)
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()
	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	restarted := stubPairSeams(t, testSecret)

	srv := newFakePairServer(t, fakePairConfig{
		pairComplete: pairCompleteFromNewMobile(t, testSecret, mobileDeviceID),
		commitFails:  true,
	})
	cfg := config.Defaults()
	cfg.Server.URL = srv.URL

	var out bytes.Buffer
	err := RunPair(paths, cfg, store, "", strings.NewReader(""), &out)
	if err == nil || !strings.Contains(err.Error(), "server did not confirm the pairing") {
		t.Fatalf("RunPair error = %v, want a server-did-not-confirm error", err)
	}
	assertFrames(t, srv, "pair_accept")
	if !restarted.Load() {
		t.Error("agent stopped for pairing should be restarted after a failed pairing")
	}

	device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
	if err != nil {
		t.Fatalf("LoadPairedDevice: %v", err)
	}
	if device != nil {
		t.Errorf("no device should be saved when the server does not commit, got %+v", device)
	}
}

// storeOldDevice pairs the host with an existing mobile, including its
// shared secret, and returns that secret.
func storeOldDevice(t *testing.T, paths config.Paths, store auth.SecretStore, deviceID string) string {
	t.Helper()
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if err := auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID:     deviceID,
		Name:         "Old Phone",
		SharedSecret: secret,
		PairedAt:     time.Now(),
	}, store); err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}
	return secret
}

func TestRunPair_RepairRejected_KeepsOldDevice(t *testing.T) {
	const (
		testSecret     = "ABCDEFGHJKLMNPQR"
		oldDeviceID    = "abc123def456abc123def456abc123de"
		mobileDeviceID = "fedcba9876543210fedcba9876543210"
	)

	tests := []struct {
		name         string
		pairSecret   string // secret the mobile keys its pairMac with
		commitFails  bool
		wantDecision string
		wantErr      string
	}{
		{"bad pairMac", "ZZZZZZZZZZZZZZZZ", false, "pair_reject", "pairing rejected"},
		{"server does not commit", testSecret, true, "pair_accept", "server did not confirm the pairing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths, store := newPairHost(t, testSecret)
			oldSecret := storeOldDevice(t, paths, store, oldDeviceID)

			srv := newFakePairServer(t, fakePairConfig{
				pairComplete: pairCompleteFromNewMobile(t, tt.pairSecret, mobileDeviceID),
				commitFails:  tt.commitFails,
			})
			cfg := config.Defaults()
			cfg.Server.URL = srv.URL

			var out bytes.Buffer
			err := RunPair(paths, cfg, store, "", strings.NewReader("y\n"), &out)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("RunPair error = %v, want it to contain %q", err, tt.wantErr)
			}
			assertFrames(t, srv, tt.wantDecision)

			device, err := auth.LoadPairedDevice(paths.PairedDevices, store)
			if err != nil {
				t.Fatalf("LoadPairedDevice: %v", err)
			}
			if device == nil || device.DeviceID != oldDeviceID {
				t.Fatalf("old device should still be paired, got %+v", device)
			}
			if device.SharedSecret != oldSecret {
				t.Error("old device's shared secret should still be stored")
			}
		})
	}
}

func TestRunPair_RepairAccepted_ReplacesOldDevice(t *testing.T) {
	const (
		testSecret     = "ABCDEFGHJKLMNPQR"
		oldDeviceID    = "abc123def456abc123def456abc123de"
		mobileDeviceID = "fedcba9876543210fedcba9876543210"
	)

	tests := []struct {
		name        string
		oldDeviceID string
	}{
		{"different device", oldDeviceID},
		{"same device", mobileDeviceID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths, store := newPairHost(t, testSecret)
			oldSecret := storeOldDevice(t, paths, store, tt.oldDeviceID)

			srv := newFakePairServer(t, fakePairConfig{pairComplete: pairCompleteFromNewMobile(t, testSecret, mobileDeviceID)})
			cfg := config.Defaults()
			cfg.Server.URL = srv.URL

			var out bytes.Buffer
			if err := RunPair(paths, cfg, store, "", strings.NewReader("y\n"), &out); err != nil {
				t.Fatalf("RunPair: %v", err)
			}
			assertFrames(t, srv, "pair_accept")

			devices, err := auth.LoadPairedDevices(paths.PairedDevices, store)
			if err != nil {
				t.Fatalf("LoadPairedDevices: %v", err)
			}
			if len(devices) != 1 || devices[0].DeviceID != mobileDeviceID {
				t.Fatalf("paired devices = %+v, want only %s", devices, mobileDeviceID)
			}
			if devices[0].SharedSecret == "" || devices[0].SharedSecret == oldSecret {
				t.Error("the new pairing's shared secret should be stored")
			}
			if tt.oldDeviceID != mobileDeviceID {
				if _, err := store.Get(auth.SharedSecretKey(tt.oldDeviceID)); !errors.Is(err, auth.ErrSecretNotFound) {
					t.Errorf("old device's shared secret should be deleted, Get error = %v", err)
				}
			}
		})
	}
}

// legacyWarning is the start of the warning RunPair prints when the server
// does not confirm support for host-confirmed pairing.
const legacyWarning = "warning: the signaling server did not confirm support for host-confirmed pairing"

// pairCompleteLowOrderKey returns a pair_complete builder whose mobile key is
// a low-order X25519 point: its pairMac is valid, but ECDH fails.
func pairCompleteLowOrderKey(secret, mobileDeviceID string) func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
	lowOrderPub := make([]byte, 32)
	return func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
		return auth.PairCompleteMessage{
			Type:                  "pair_complete",
			MobileDeviceID:        mobileDeviceID,
			MobileX25519PublicKey: base64.StdEncoding.EncodeToString(lowOrderPub),
			PairMac:               pairMacForTest(secret, lowOrderPub, mobileDeviceID),
		}
	}
}

func TestRunPair_LegacyServer(t *testing.T) {
	const (
		testSecret     = "ABCDEFGHJKLMNPQR"
		mobileDeviceID = "fedcba9876543210fedcba9876543210"
	)

	tests := []struct {
		name         string
		pairComplete func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage
		wantErr      string // empty means the device is stored
		wantDeletes  int32
	}{
		{
			name:         "valid pairMac stores device",
			pairComplete: pairCompleteFromNewMobile(t, testSecret, mobileDeviceID),
		},
		{
			name:         "bad pairMac deletes server pairing",
			pairComplete: pairCompleteFromNewMobile(t, "ZZZZZZZZZZZZZZZZ", mobileDeviceID),
			wantErr:      errPairMACRejected.Error(),
			wantDeletes:  1,
		},
		{
			name:         "low-order mobile key deletes server pairing",
			pairComplete: pairCompleteLowOrderKey(testSecret, mobileDeviceID),
			wantErr:      "key exchange failed",
			wantDeletes:  1,
		},
		{
			name:         "invalid mobile device ID deletes server pairing",
			pairComplete: pairCompleteFromNewMobile(t, testSecret, "NOT-A-VALID-ID"),
			wantErr:      "invalid device ID",
			wantDeletes:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths, store := newPairHost(t, testSecret)

			srv := newFakePairServer(t, fakePairConfig{
				pairComplete: tt.pairComplete,
				legacy:       true,
			})
			cfg := config.Defaults()
			cfg.Server.URL = srv.URL

			var out bytes.Buffer
			err := RunPair(paths, cfg, store, "", strings.NewReader(""), &out)
			// A legacy server committed at pair_complete, so the host must
			// not send a decision it would answer with an error.
			assertFrames(t, srv)
			if got := srv.deletes.Load(); got != tt.wantDeletes {
				t.Errorf("DELETE /v1/auth/pairing calls = %d, want %d", got, tt.wantDeletes)
			}
			if !strings.Contains(out.String(), legacyWarning) {
				t.Errorf("expected the legacy-server warning, got output: %s", out.String())
			}

			device, loadErr := auth.LoadPairedDevice(paths.PairedDevices, store)
			if loadErr != nil {
				t.Fatalf("LoadPairedDevice: %v", loadErr)
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("RunPair error = %v, want it to contain %q", err, tt.wantErr)
				}
				if device != nil {
					t.Errorf("no device should be saved, got %+v", device)
				}
				return
			}
			if err != nil {
				t.Fatalf("RunPair: %v", err)
			}
			if device == nil || device.DeviceID != mobileDeviceID || device.SharedSecret == "" {
				t.Fatalf("paired device = %+v, want %s with a shared secret", device, mobileDeviceID)
			}
		})
	}
}

func TestRunPair_LegacyServerRepair_RemovesOldDevice(t *testing.T) {
	const (
		testSecret     = "ABCDEFGHJKLMNPQR"
		oldDeviceID    = "abc123def456abc123def456abc123de"
		mobileDeviceID = "fedcba9876543210fedcba9876543210"
	)

	tests := []struct {
		name        string
		oldDeviceID string
		pairSecret  string // secret the mobile keys its pairMac with
		wantPaired  bool
	}{
		{"success with a different device", oldDeviceID, testSecret, true},
		{"success with the same device", mobileDeviceID, testSecret, true},
		{"bad pairMac", oldDeviceID, "ZZZZZZZZZZZZZZZZ", false},
		{"bad pairMac from the same device", mobileDeviceID, "ZZZZZZZZZZZZZZZZ", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths, store := newPairHost(t, testSecret)
			oldSecret := storeOldDevice(t, paths, store, tt.oldDeviceID)

			srv := newFakePairServer(t, fakePairConfig{
				pairComplete: pairCompleteFromNewMobile(t, tt.pairSecret, mobileDeviceID),
				legacy:       true,
			})
			cfg := config.Defaults()
			cfg.Server.URL = srv.URL

			var out bytes.Buffer
			err := RunPair(paths, cfg, store, "", strings.NewReader("y\n"), &out)
			assertFrames(t, srv)
			// A stored re-pair of the same device replaced it, so only a
			// different or unstored device was unpaired.
			wantNotice := !tt.wantPaired || tt.oldDeviceID != mobileDeviceID
			if got := strings.Contains(out.String(), "The server unpaired the previous device 'Old Phone'."); got != wantNotice {
				t.Errorf("previous-device notice shown = %t, want %t; output: %s", got, wantNotice, out.String())
			}

			devices, loadErr := auth.LoadPairedDevices(paths.PairedDevices, store)
			if loadErr != nil {
				t.Fatalf("LoadPairedDevices: %v", loadErr)
			}

			if !tt.wantPaired {
				if !errors.Is(err, errPairMACRejected) {
					t.Errorf("RunPair error = %v, want errPairMACRejected", err)
				}
				if got := srv.deletes.Load(); got != 1 {
					t.Errorf("DELETE /v1/auth/pairing calls = %d, want 1", got)
				}
				if len(devices) != 0 {
					t.Errorf("paired devices = %+v, want none", devices)
				}
				if _, err := store.Get(auth.SharedSecretKey(tt.oldDeviceID)); !errors.Is(err, auth.ErrSecretNotFound) {
					t.Errorf("old device's shared secret should be deleted, Get error = %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("RunPair: %v", err)
			}
			if got := srv.deletes.Load(); got != 0 {
				t.Errorf("DELETE /v1/auth/pairing calls = %d, want 0", got)
			}
			if len(devices) != 1 || devices[0].DeviceID != mobileDeviceID {
				t.Fatalf("paired devices = %+v, want only %s", devices, mobileDeviceID)
			}
			if devices[0].SharedSecret == "" || devices[0].SharedSecret == oldSecret {
				t.Error("the new pairing's shared secret should be stored")
			}
			if tt.oldDeviceID != mobileDeviceID {
				if _, err := store.Get(auth.SharedSecretKey(tt.oldDeviceID)); !errors.Is(err, auth.ErrSecretNotFound) {
					t.Errorf("old device's shared secret should be deleted, Get error = %v", err)
				}
			}
		})
	}
}

func TestRunPair_ExistingPairing_PromptLabel(t *testing.T) {
	tests := []struct {
		name      string
		deviceID  string
		wantLabel string
	}{
		{"short device ID", "abc", "abc"},
		{"12-character device ID", "abc123def456", "abc123def456"},
		{"long device ID", "abc123def456abc123def456abc123de", "abc123def456..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := testPaths(t)
			store := auth.NewMemorySecretStore()
			if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
				t.Fatalf("GenerateIdentity: %v", err)
			}
			// SavePairedDevices skips AddPairedDevice's ID validation, so a
			// malformed file can hold any ID.
			if err := auth.SavePairedDevices(paths.PairedDevices, []auth.PairedDevice{{
				DeviceID: tt.deviceID,
				PairedAt: time.Now(),
			}}); err != nil {
				t.Fatalf("SavePairedDevices: %v", err)
			}

			var out bytes.Buffer
			if err := RunPair(paths, config.Defaults(), store, "", strings.NewReader("n\n"), &out); err != nil {
				t.Fatalf("RunPair should return nil on decline, got: %v", err)
			}
			if !strings.Contains(out.String(), "A device is already paired: "+tt.wantLabel+" (paired ") {
				t.Errorf("expected label %q in prompt, got: %s", tt.wantLabel, out.String())
			}
		})
	}
}

func TestRunPair_SanitizesServerErrors(t *testing.T) {
	type testCase struct {
		name    string
		failAt  string // "initiate", "token", "ws" or "wsclose"
		body    string
		wantErr string
	}
	var tests []testCase
	for _, b := range hostileServerBodies {
		tests = append(tests,
			testCase{"initiate " + b.name, "initiate", b.body, "failed to initiate pairing: server error (500): internal error"},
			testCase{"token " + b.name, "token", b.body, "failed to authenticate: server error (500): internal error"},
		)
	}
	tests = append(tests, testCase{
		name:    "ws auth error",
		failAt:  "ws",
		body:    `{"type":"error","error":"internal error\u001b]52;c;ZXZpbA==\u0007\u001b[2K\r\u009b"}`,
		wantErr: "pairing failed: WebSocket auth failed: internal error",
	}, testCase{
		name:    "ws close reason",
		failAt:  "wsclose",
		body:    "internal error\x1b]52;c;ZXZpbA==\x07\x1b[2K\r\u009b",
		wantErr: "pairing failed: read auth response: websocket: close 1011 (internal server error): internal error",
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			paths := testPaths(t)
			store := auth.NewMemorySecretStore()
			if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
				t.Fatalf("GenerateIdentity: %v", err)
			}
			// Failures after the agent is stopped restart it; don't spawn one from the test.
			origEnsure := ensureAgentRunning
			t.Cleanup(func() { ensureAgentRunning = origEnsure })
			ensureAgentRunning = func(config.Paths, auth.SecretStore) error { return nil }

			upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
			fail := func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, tt.body)
			}
			mux := http.NewServeMux()
			mux.HandleFunc("POST /v1/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `{"nonce":"test-nonce"}`)
			})
			mux.HandleFunc("POST /v1/auth/pair/initiate", func(w http.ResponseWriter, r *http.Request) {
				if tt.failAt == "initiate" {
					fail(w)
					return
				}
				fmt.Fprint(w, `{"pairingCode":"ABC234"}`)
			})
			mux.HandleFunc("POST /v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
				if tt.failAt == "token" {
					fail(w)
					return
				}
				fmt.Fprint(w, `{"token":"test-jwt"}`)
			})
			mux.HandleFunc("GET /v1/ws", func(w http.ResponseWriter, r *http.Request) {
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				if _, _, err := conn.ReadMessage(); err != nil { // auth
					return
				}
				if tt.failAt == "wsclose" {
					conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInternalServerErr, tt.body)) //nolint:errcheck // client reports read failures
					return
				}
				conn.WriteMessage(websocket.TextMessage, []byte(tt.body)) //nolint:errcheck // client reports read failures
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			cfg := config.Defaults()
			cfg.Server.URL = srv.URL

			var out bytes.Buffer
			err := RunPair(paths, cfg, store, "", strings.NewReader(""), &out)
			if err == nil {
				t.Fatal("expected RunPair error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("RunPair error = %q, want it to contain %q", err, tt.wantErr)
			}
			assertNoControlBytes(t, err.Error())
		})
	}
}

func TestRunPair_ExistingPairing_AcceptButServerDown(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	oldSecret := storeOldDevice(t, paths, store, "abc123def456abc123def456abc123de")

	// Point to a server that will refuse connections
	cfg := config.Defaults()
	cfg.Server.URL = "http://127.0.0.1:1"

	var out bytes.Buffer
	in := strings.NewReader("y\n")

	err := RunPair(paths, cfg, store, "", in, &out)
	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
	if !strings.Contains(err.Error(), "failed to initiate pairing") {
		t.Errorf("expected 'failed to initiate pairing' error, got: %v", err)
	}

	// The old device is replaced only once the server commits the new
	// pairing, so an unreachable server leaves it in place.
	device, loadErr := auth.LoadPairedDevice(paths.PairedDevices, store)
	if loadErr != nil {
		t.Fatalf("LoadPairedDevice: %v", loadErr)
	}
	if device == nil {
		t.Fatal("old device should be kept when the new pairing never reaches the server")
	}
	if device.SharedSecret != oldSecret {
		t.Error("old device's shared secret should still be stored")
	}
}
