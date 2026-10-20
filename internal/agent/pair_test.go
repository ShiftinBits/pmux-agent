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

// fakePairServer emulates the signaling server endpoints used by RunPair and
// plays the mobile: once the host has initiated pairing, the WebSocket
// delivers a pair_complete built by makePairComplete from the host's
// X25519 public key and device ID.
type fakePairServer struct {
	*httptest.Server

	mu         sync.Mutex
	hostPub    []byte
	hostDevice string
}

func newFakePairServer(t *testing.T, makePairComplete func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage) *fakePairServer {
	t.Helper()
	fs := &fakePairServer{}
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/challenge", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"nonce":"test-nonce"}`)
	})
	mux.HandleFunc("POST /v1/auth/pair/initiate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			DeviceID     string `json:"deviceId"`
			X25519PubKey string `json:"x25519PublicKey"`
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
		fs.mu.Unlock()
		fmt.Fprint(w, `{"pairingCode":"ABC234"}`)
	})
	mux.HandleFunc("POST /v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
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
		if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth_ok"}`)); err != nil {
			return
		}

		fs.mu.Lock()
		msg := makePairComplete(fs.hostPub, fs.hostDevice)
		fs.mu.Unlock()
		data, err := json.Marshal(msg)
		if err != nil {
			return
		}
		conn.WriteMessage(websocket.TextMessage, data) //nolint:errcheck // client reports read failures
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

func pairMacForTest(secret string, bind []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte("pocketmux-pair-mac-v2"))
	h.Write(bind)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
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

	tests := []struct {
		name         string
		pairComplete func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage
		wantPaired   bool
	}{
		{
			name: "valid pairMac saves device",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        mobileDeviceID,
					MobileX25519PublicKey: mobilePubB64,
					MobileName:            "Test Phone",
					PairMac:               pairMacForTest(testSecret, pairBindForTest(hostPub, mobilePub, hostDeviceID, mobileDeviceID)),
				}
			},
			wantPaired: true,
		},
		{
			name: "pairMac with wrong secret aborts",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        mobileDeviceID,
					MobileX25519PublicKey: mobilePubB64,
					PairMac:               pairMacForTest("ZZZZZZZZZZZZZZZZ", pairBindForTest(hostPub, mobilePub, hostDeviceID, mobileDeviceID)),
				}
			},
		},
		{
			name: "substituted mobile key aborts",
			pairComplete: func(hostPub []byte, hostDeviceID string) auth.PairCompleteMessage {
				return auth.PairCompleteMessage{
					Type:                  "pair_complete",
					MobileDeviceID:        mobileDeviceID,
					MobileX25519PublicKey: attackerPubB64,
					PairMac:               pairMacForTest(testSecret, pairBindForTest(hostPub, mobilePub, hostDeviceID, mobileDeviceID)),
				}
			},
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

			origSecret, origEnsure := generatePairingSecret, ensureAgentRunning
			t.Cleanup(func() { generatePairingSecret, ensureAgentRunning = origSecret, origEnsure })
			generatePairingSecret = func() (string, error) { return testSecret, nil }
			var restarted atomic.Bool
			ensureAgentRunning = func(config.Paths, auth.SecretStore) error {
				restarted.Store(true)
				return nil
			}

			srv := newFakePairServer(t, tt.pairComplete)
			cfg := config.Defaults()
			cfg.Server.URL = srv.URL

			var out bytes.Buffer
			err = RunPair(paths, cfg, store, "", strings.NewReader(""), &out)

			if !strings.Contains(out.String(), "Manual pairing code: ABC234-ABCD-EFGH-JKLM-NPQR") {
				t.Errorf("expected manual code with secret in output, got: %s", out.String())
			}

			device, loadErr := auth.LoadPairedDevice(paths.PairedDevices, store)
			if loadErr != nil {
				t.Fatalf("LoadPairedDevice: %v", loadErr)
			}

			if !tt.wantPaired {
				if !errors.Is(err, errPairMACRejected) {
					t.Fatalf("RunPair error = %v, want errPairMACRejected", err)
				}
				if device != nil {
					t.Errorf("no device should be saved, got %+v", device)
				}
				if restarted.Load() {
					t.Error("agent should not be restarted after a rejected pairing")
				}
				return
			}

			if err != nil {
				t.Fatalf("RunPair: %v", err)
			}
			if device == nil {
				t.Fatal("expected paired device to be saved")
			}
			if device.DeviceID != mobileDeviceID {
				t.Errorf("DeviceID = %q, want %q", device.DeviceID, mobileDeviceID)
			}
			if device.Name != "Test Phone" {
				t.Errorf("Name = %q, want %q", device.Name, "Test Phone")
			}
			if !restarted.Load() {
				t.Error("agent should be restarted after pairing")
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

func TestRunPair_ExistingPairing_AcceptButServerDown(t *testing.T) {
	paths := testPaths(t)
	store := auth.NewMemorySecretStore()

	if _, err := auth.GenerateIdentity(paths.KeysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	err := auth.AddPairedDevice(paths.PairedDevices, auth.PairedDevice{
		DeviceID: "abc123def456abc123def456abc123de",
		Name:     "Old Phone",
		PairedAt: time.Now(),
	}, store)
	if err != nil {
		t.Fatalf("AddPairedDevice: %v", err)
	}

	// Point to a server that will refuse connections
	cfg := config.Defaults()
	cfg.Server.URL = "http://127.0.0.1:1"

	var out bytes.Buffer
	in := strings.NewReader("y\n")

	err = RunPair(paths, cfg, store, "", in, &out)
	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
	if !strings.Contains(err.Error(), "failed to initiate pairing") {
		t.Errorf("expected 'failed to initiate pairing' error, got: %v", err)
	}

	// Verify old device was removed (user accepted replacement)
	device, loadErr := auth.LoadPairedDevice(paths.PairedDevices, store)
	if loadErr != nil {
		t.Fatalf("LoadPairedDevice: %v", loadErr)
	}
	if device != nil {
		t.Error("old device should have been removed after user accepted replacement")
	}
}
