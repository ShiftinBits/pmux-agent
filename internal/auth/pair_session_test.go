package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestInitiatePairing(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	t.Run("successful initiation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/auth/pair/initiate" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("unexpected method: %s", r.Method)
			}

			var body struct {
				DeviceID       string `json:"deviceId"`
				PublicKey      string `json:"publicKey"`
				X25519PubKey   string `json:"x25519PublicKey"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if body.DeviceID != id.DeviceID {
				t.Errorf("deviceId = %q, want %q", body.DeviceID, id.DeviceID)
			}
			if body.PublicKey == "" {
				t.Error("publicKey is empty")
			}
			if body.X25519PubKey == "" {
				t.Error("x25519PublicKey is empty")
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"pairingCode":"ABC123"}`))
		}))
		defer server.Close()

		resp, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host")
		if err != nil {
			t.Fatalf("InitiatePairing() error: %v", err)
		}
		if resp.PairingCode != "ABC123" {
			t.Errorf("pairingCode = %q, want %q", resp.PairingCode, "ABC123")
		}
	})

	t.Run("server returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"Missing required fields"}`))
		}))
		defer server.Close()

		_, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "server error (400)") {
			t.Errorf("error = %q, want substring %q", err.Error(), "server error (400)")
		}
	})

	t.Run("server returns empty pairing code", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"pairingCode":""}`))
		}))
		defer server.Close()

		_, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "empty pairing code") {
			t.Errorf("error = %q, want substring %q", err.Error(), "empty pairing code")
		}
	})

	t.Run("network error", func(t *testing.T) {
		_, err := InitiatePairing(id, "x25519key==", "http://localhost:1", http.DefaultClient, "test-host")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestWaitForPairComplete(t *testing.T) {
	t.Run("receives pair_complete message", func(t *testing.T) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Fatalf("upgrade error: %v", err)
			}
			defer conn.Close()

			// Read auth message
			_, authData, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("read auth: %v", err)
			}
			var authMsg struct {
				Type  string `json:"type"`
				Token string `json:"token"`
			}
			json.Unmarshal(authData, &authMsg)
			if authMsg.Type != "auth" {
				t.Errorf("auth type = %q, want %q", authMsg.Type, "auth")
			}

			// Send auth_ok response
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth_ok"}`))

			// Send pair_complete
			pairMsg := PairCompleteMessage{
				Type:                  "pair_complete",
				MobileDeviceID:        "mobile-xyz",
				MobileX25519PublicKey: "mobileX25519Key==",
			}
			data, _ := json.Marshal(pairMsg)
			conn.WriteMessage(websocket.TextMessage, data)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		msg, err := WaitForPairComplete(ctx, server.URL, "test-jwt")
		if err != nil {
			t.Fatalf("WaitForPairComplete() error: %v", err)
		}
		if msg.MobileDeviceID != "mobile-xyz" {
			t.Errorf("mobileDeviceId = %q, want %q", msg.MobileDeviceID, "mobile-xyz")
		}
		if msg.MobileX25519PublicKey != "mobileX25519Key==" {
			t.Errorf("mobileX25519PublicKey = %q, want %q", msg.MobileX25519PublicKey, "mobileX25519Key==")
		}
	})

	t.Run("ignores non-pair_complete messages", func(t *testing.T) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()

			conn.ReadMessage() // auth
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth_ok"}`))

			// Send a presence ack first (should be ignored)
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"presence_ack"}`))

			// Then send pair_complete
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"pair_complete","mobileDeviceId":"m1","mobileX25519PublicKey":"key=="}`))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		msg, err := WaitForPairComplete(ctx, server.URL, "test-jwt")
		if err != nil {
			t.Fatalf("WaitForPairComplete() error: %v", err)
		}
		if msg.MobileDeviceID != "m1" {
			t.Errorf("mobileDeviceId = %q, want %q", msg.MobileDeviceID, "m1")
		}
	})

	t.Run("times out when no pair_complete received", func(t *testing.T) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()

			conn.ReadMessage() // auth
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth_ok"}`))

			// Don't send pair_complete — let it timeout
			time.Sleep(2 * time.Second)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		_, err := WaitForPairComplete(ctx, server.URL, "test-jwt")
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Errorf("error = %q, want substring %q", err.Error(), "timed out")
		}
	})

	t.Run("fails on WebSocket auth error", func(t *testing.T) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()

			conn.ReadMessage() // auth
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","error":"Invalid token"}`))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := WaitForPairComplete(ctx, server.URL, "bad-jwt")
		if err == nil {
			t.Fatal("expected auth error, got nil")
		}
		if !strings.Contains(err.Error(), "WebSocket auth failed") {
			t.Errorf("error = %q, want substring %q", err.Error(), "WebSocket auth failed")
		}
	})
}
