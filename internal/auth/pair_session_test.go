package auth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
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

	const testNonce = "pair-nonce-xyz789"

	// pairHandler wraps a /auth/pair/initiate handler, serving nonces at /auth/challenge.
	pairHandler := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/auth/challenge" && r.Method == "POST" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"nonce":"` + testNonce + `"}`))
				return
			}
			h(w, r)
		}
	}

	t.Run("successful initiation", func(t *testing.T) {
		server := httptest.NewServer(pairHandler(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/auth/pair/initiate" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("unexpected method: %s", r.Method)
			}

			var body struct {
				DeviceID         string `json:"deviceId"`
				Ed25519PublicKey string `json:"ed25519PublicKey"`
				X25519PubKey     string `json:"x25519PublicKey"`
				Nonce            string `json:"nonce"`
				Signature        string `json:"signature"`
				PairConfirm      bool   `json:"pairConfirm"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if !body.PairConfirm {
				t.Error("pairConfirm = false, want true")
			}
			if body.DeviceID != id.DeviceID {
				t.Errorf("deviceId = %q, want %q", body.DeviceID, id.DeviceID)
			}
			if body.Ed25519PublicKey == "" {
				t.Error("ed25519PublicKey is empty")
			}
			if body.X25519PubKey == "" {
				t.Error("x25519PublicKey is empty")
			}
			if body.Nonce != testNonce {
				t.Errorf("nonce = %q, want %q", body.Nonce, testNonce)
			}
			if body.Signature == "" {
				t.Error("signature is empty")
			}

			// Verify the signature is over deviceID + "|" + nonce
			pubKeyBytes, err := base64.StdEncoding.DecodeString(body.Ed25519PublicKey)
			if err != nil {
				t.Fatalf("decode publicKey: %v", err)
			}
			sigBytes, err := base64.StdEncoding.DecodeString(body.Signature)
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			message := []byte(body.DeviceID + "|" + body.Nonce)
			if !ed25519.Verify(ed25519.PublicKey(pubKeyBytes), message, sigBytes) {
				t.Error("signature verification failed")
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"pairingCode":"ABC234"}`))
		}))
		defer server.Close()

		resp, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host", "")
		if err != nil {
			t.Fatalf("InitiatePairing() error: %v", err)
		}
		if resp.PairingCode != "ABC234" {
			t.Errorf("pairingCode = %q, want %q", resp.PairingCode, "ABC234")
		}
	})

	t.Run("challenge fetch error propagates", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/auth/challenge" {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"internal error"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"pairingCode":"ABC234"}`))
		}))
		defer server.Close()

		_, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host", "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "server error (500)") {
			t.Errorf("error = %q, want substring %q", err.Error(), "server error (500)")
		}
	})

	t.Run("server returns error on pair initiate", func(t *testing.T) {
		server := httptest.NewServer(pairHandler(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"Missing required fields"}`))
		}))
		defer server.Close()

		_, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host", "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "server error (400)") {
			t.Errorf("error = %q, want substring %q", err.Error(), "server error (400)")
		}
	})

	for _, tc := range []struct{ name, code string }{
		{"empty", ""},
		{"too short", "ABC23"},
		{"too long", "ABC2345"},
		{"QR delimiter", "ABC|23"},
		{"manual-code delimiter", "ABC-23"},
		{"outside alphabet", "ABC123"},
	} {
		t.Run("server returns invalid pairing code: "+tc.name, func(t *testing.T) {
			server := httptest.NewServer(pairHandler(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"pairingCode":%q}`, tc.code)
			}))
			defer server.Close()

			_, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host", "")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "invalid pairing code") {
				t.Errorf("error = %q, want substring %q", err.Error(), "invalid pairing code")
			}
		})
	}

	t.Run("oversized response body is truncated", func(t *testing.T) {
		server := httptest.NewServer(pairHandler(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			// Send a response body larger than 64KB — the LimitReader should truncate it,
			// causing JSON unmarshal to fail (incomplete JSON).
			big := make([]byte, 128*1024)
			for i := range big {
				big[i] = 'x'
			}
			w.Write(big)
		}))
		defer server.Close()

		_, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host", "")
		if err == nil {
			t.Fatal("expected error for oversized response, got nil")
		}
		if !strings.Contains(err.Error(), "parse pair initiate response") {
			t.Errorf("error = %q, want substring %q", err.Error(), "parse pair initiate response")
		}
	})

	t.Run("network error", func(t *testing.T) {
		_, err := InitiatePairing(id, "x25519key==", "http://localhost:1", http.DefaultClient, "test-host", "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestPairCompleteMessageDeserialization(t *testing.T) {
	t.Run("deserializes mobileName", func(t *testing.T) {
		raw := `{"type":"pair_complete","mobileDeviceId":"dd44ee55ff66aa11bb22cc33dd44ee55","mobileX25519PublicKey":"key==","mobileName":"My iPhone","pairMac":"mac=="}`
		var msg PairCompleteMessage
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if msg.Type != "pair_complete" {
			t.Errorf("Type = %q, want %q", msg.Type, "pair_complete")
		}
		if msg.MobileDeviceID != "dd44ee55ff66aa11bb22cc33dd44ee55" {
			t.Errorf("MobileDeviceID = %q, want %q", msg.MobileDeviceID, "dd44ee55ff66aa11bb22cc33dd44ee55")
		}
		if msg.MobileX25519PublicKey != "key==" {
			t.Errorf("MobileX25519PublicKey = %q, want %q", msg.MobileX25519PublicKey, "key==")
		}
		if msg.MobileName != "My iPhone" {
			t.Errorf("MobileName = %q, want %q", msg.MobileName, "My iPhone")
		}
		if msg.PairMac != "mac==" {
			t.Errorf("PairMac = %q, want %q", msg.PairMac, "mac==")
		}
	})

	t.Run("handles missing mobileName", func(t *testing.T) {
		raw := `{"type":"pair_complete","mobileDeviceId":"ee55ff66aa11bb22cc33dd44ee55ff66","mobileX25519PublicKey":"key2=="}`
		var msg PairCompleteMessage
		if err := json.Unmarshal([]byte(raw), &msg); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if msg.MobileDeviceID != "ee55ff66aa11bb22cc33dd44ee55ff66" {
			t.Errorf("MobileDeviceID = %q, want %q", msg.MobileDeviceID, "ee55ff66aa11bb22cc33dd44ee55ff66")
		}
		if msg.MobileName != "" {
			t.Errorf("MobileName = %q, want empty string", msg.MobileName)
		}
		if msg.PairMac != "" {
			t.Errorf("PairMac = %q, want empty string", msg.PairMac)
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
				MobileDeviceID:        "bb22cc33dd44ee55ff66aa11bb22cc33",
				MobileX25519PublicKey: "mobileX25519Key==",
				PairMac:               "pairMac==",
			}
			data, _ := json.Marshal(pairMsg)
			conn.WriteMessage(websocket.TextMessage, data)
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		sess, err := WaitForPairComplete(ctx, server.URL, "test-jwt", "")
		if err != nil {
			t.Fatalf("WaitForPairComplete() error: %v", err)
		}
		defer sess.Close()
		msg := sess.Message
		if msg.MobileDeviceID != "bb22cc33dd44ee55ff66aa11bb22cc33" {
			t.Errorf("mobileDeviceId = %q, want %q", msg.MobileDeviceID, "bb22cc33dd44ee55ff66aa11bb22cc33")
		}
		if msg.MobileX25519PublicKey != "mobileX25519Key==" {
			t.Errorf("mobileX25519PublicKey = %q, want %q", msg.MobileX25519PublicKey, "mobileX25519Key==")
		}
		if msg.PairMac != "pairMac==" {
			t.Errorf("pairMac = %q, want %q", msg.PairMac, "pairMac==")
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
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"pair_complete","mobileDeviceId":"cc33dd44ee55ff66aa11bb22cc33dd44","mobileX25519PublicKey":"key=="}`))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		sess, err := WaitForPairComplete(ctx, server.URL, "test-jwt", "")
		if err != nil {
			t.Fatalf("WaitForPairComplete() error: %v", err)
		}
		defer sess.Close()
		msg := sess.Message
		if msg.MobileDeviceID != "cc33dd44ee55ff66aa11bb22cc33dd44" {
			t.Errorf("mobileDeviceId = %q, want %q", msg.MobileDeviceID, "cc33dd44ee55ff66aa11bb22cc33dd44")
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

		_, err := WaitForPairComplete(ctx, server.URL, "test-jwt", "")
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Errorf("error = %q, want substring %q", err.Error(), "timed out")
		}
	})

	t.Run("rejects invalid MobileDeviceID format", func(t *testing.T) {
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()

			conn.ReadMessage() // auth
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth_ok"}`))

			// Send pair_complete with an invalid device ID (not 32 hex chars)
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"pair_complete","mobileDeviceId":"INVALID-ID!","mobileX25519PublicKey":"key=="}`))
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := WaitForPairComplete(ctx, server.URL, "test-jwt", "")
		if err == nil {
			t.Fatal("expected validation error, got nil")
		}
		if !strings.Contains(err.Error(), "invalid device ID") {
			t.Errorf("error = %q, want substring %q", err.Error(), "invalid device ID")
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

		_, err := WaitForPairComplete(ctx, server.URL, "bad-jwt", "")
		if err == nil {
			t.Fatal("expected auth error, got nil")
		}
		if !strings.Contains(err.Error(), "WebSocket auth failed") {
			t.Errorf("error = %q, want substring %q", err.Error(), "WebSocket auth failed")
		}
	})

	// afterAuth runs a server that accepts the auth message and then hands the
	// connection to send.
	afterAuth := func(t *testing.T, send func(*websocket.Conn)) error {
		t.Helper()
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.ReadMessage() // auth
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth_ok"}`))
			send(conn)
			conn.ReadMessage() // hold the connection until the client hangs up
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := WaitForPairComplete(ctx, server.URL, "test-jwt", "")
		return err
	}

	t.Run("rejects oversized message", func(t *testing.T) {
		err := afterAuth(t, func(conn *websocket.Conn) {
			conn.WriteMessage(websocket.TextMessage, make([]byte, maxPairMessageSize+1))
		})
		if err == nil || !strings.Contains(err.Error(), "read limit") {
			t.Errorf("error = %v, want a read limit error", err)
		}
	})

	t.Run("sanitizes server close reason", func(t *testing.T) {
		err := afterAuth(t, func(conn *websocket.Conn) {
			conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "bad\x1b]0;pwn\x07"))
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if strings.ContainsAny(err.Error(), "\x1b\x07") {
			t.Errorf("error %q contains control characters", err.Error())
		}
	})
}

func TestPairSession(t *testing.T) {
	const mobileID = "bb22cc33dd44ee55ff66aa11bb22cc33"

	// open runs a server that delivers pair_complete, forwards the host's next
	// frame on decisions, hands the connection to respond, and holds it until
	// the client hangs up.
	open := func(t *testing.T, respond func(*websocket.Conn)) (*PairSession, <-chan []byte) {
		t.Helper()
		decisions := make(chan []byte, 1)
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.ReadMessage() // auth
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth_ok"}`))
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"pair_complete","mobileDeviceId":"`+mobileID+`","mobileX25519PublicKey":"key=="}`))
			_, decision, err := conn.ReadMessage()
			if err != nil {
				return
			}
			decisions <- decision
			respond(conn)
			conn.ReadMessage() // hold the connection until the client hangs up
		}))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sess, err := WaitForPairComplete(ctx, server.URL, "test-jwt", "")
		if err != nil {
			t.Fatalf("WaitForPairComplete() error: %v", err)
		}
		t.Cleanup(func() { sess.Close() })
		return sess, decisions
	}

	// assertDecision checks the host's frame is exactly {type, mobileDeviceId}.
	assertDecision := func(t *testing.T, decisions <-chan []byte, wantType string) {
		t.Helper()
		var data []byte
		select {
		case data = <-decisions:
		case <-time.After(5 * time.Second):
			t.Fatal("server received no decision frame")
		}
		var got map[string]any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("decision frame %q is not JSON: %v", data, err)
		}
		want := map[string]any{"type": wantType, "mobileDeviceId": mobileID}
		if len(got) != len(want) || got["type"] != want["type"] || got["mobileDeviceId"] != want["mobileDeviceId"] {
			t.Errorf("decision frame = %s, want %v", data, want)
		}
	}

	send := func(frames ...string) func(*websocket.Conn) {
		return func(conn *websocket.Conn) {
			for _, f := range frames {
				conn.WriteMessage(websocket.TextMessage, []byte(f))
			}
		}
	}

	acceptTests := []struct {
		name    string
		respond func(*websocket.Conn)
		timeout time.Duration
		wantErr string // "" means Accept succeeds
	}{
		{
			name:    "confirmed",
			respond: send(`{"type":"pair_result","mobileDeviceId":"` + mobileID + `","ok":true}`),
		},
		{
			name: "skips unrelated frames",
			respond: send(
				`{"type":"presence_ack"}`,
				`not json`,
				`{"type":"pair_result","mobileDeviceId":"cc33dd44ee55ff66aa11bb22cc33dd44","ok":false}`,
				`{"type":"pair_result","mobileDeviceId":"`+mobileID+`","ok":true}`,
			),
		},
		{
			name:    "not committed",
			respond: send(`{"type":"pair_result","mobileDeviceId":"` + mobileID + `","ok":false}`),
			wantErr: "server did not confirm the pairing (the mobile may have timed out)",
		},
		{
			name:    "server without confirmed pairing",
			respond: send(`{"type":"error","error":"Unknown message type: pair_accept\u001b]0;pwn\u0007"}`),
			wantErr: "server does not support confirmed pairing; it may need updating: Unknown message type: pair_accept",
		},
		{
			name:    "no answer",
			respond: func(*websocket.Conn) {},
			timeout: 200 * time.Millisecond,
			wantErr: "wait for pair_result",
		},
	}
	for _, tt := range acceptTests {
		t.Run("Accept "+tt.name, func(t *testing.T) {
			sess, decisions := open(t, tt.respond)
			timeout := tt.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}

			err := sess.Accept(timeout)
			assertDecision(t, decisions, "pair_accept")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Accept() error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Accept() error = %v, want it to contain %q", err, tt.wantErr)
			}
			if strings.ContainsAny(err.Error(), "\x1b\x07") {
				t.Errorf("error %q contains control characters", err.Error())
			}
		})
	}

	t.Run("Reject", func(t *testing.T) {
		sess, decisions := open(t, func(*websocket.Conn) {})
		if err := sess.Reject(); err != nil {
			t.Fatalf("Reject() error: %v", err)
		}
		assertDecision(t, decisions, "pair_reject")
	})
}
