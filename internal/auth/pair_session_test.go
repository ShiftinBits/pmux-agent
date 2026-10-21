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
			w.Write([]byte(`{"pairingCode":"ABC234","pairConfirm":true}`))
		}))
		defer server.Close()

		resp, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host", "")
		if err != nil {
			t.Fatalf("InitiatePairing() error: %v", err)
		}
		if resp.PairingCode != "ABC234" {
			t.Errorf("pairingCode = %q, want %q", resp.PairingCode, "ABC234")
		}
		if !resp.PairConfirm {
			t.Error("PairConfirm = false, want the server's echo")
		}
	})

	t.Run("server without confirmed pairing", func(t *testing.T) {
		server := httptest.NewServer(pairHandler(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"pairingCode":"ABC234"}`))
		}))
		defer server.Close()

		resp, err := InitiatePairing(id, "x25519key==", server.URL, server.Client(), "test-host", "")
		if err != nil {
			t.Fatalf("InitiatePairing() error: %v", err)
		}
		if resp.PairConfirm {
			t.Error("PairConfirm = true, want false when the server does not echo it")
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

// authOK is the server's reply to a successful WebSocket auth.
const authOK = `{"type":"auth","status":"ok"}`

// pairServer runs a WebSocket server that reads the host's auth message,
// hands the connection to serve, and then holds it until the client hangs up.
func pairServer(t *testing.T, serve func(*websocket.Conn)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		if _, _, err := conn.ReadMessage(); err != nil { // auth
			return
		}
		serve(conn)
		for { // hold the connection until the client hangs up
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// sendFrames returns a serve func that writes frames as text messages.
func sendFrames(frames ...string) func(*websocket.Conn) {
	return func(conn *websocket.Conn) {
		for _, f := range frames {
			conn.WriteMessage(websocket.TextMessage, []byte(f))
		}
	}
}

// dialAndWait dials a confirmed session to server and waits up to timeout
// for pair_complete. The session, if any, is closed when the test ends.
func dialAndWait(t *testing.T, server *httptest.Server, timeout time.Duration) (*PairCompleteMessage, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	sess, err := DialPairSession(ctx, server.URL, "test-jwt", "", true)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { sess.Close() })
	return sess.WaitForPairComplete(ctx)
}

func TestWaitForPairComplete(t *testing.T) {
	const pairComplete = `{"type":"pair_complete","mobileDeviceId":"bb22cc33dd44ee55ff66aa11bb22cc33","mobileX25519PublicKey":"mobileX25519Key==","pairMac":"pairMac=="}`

	t.Run("sends auth with the JWT", func(t *testing.T) {
		authFrames := make(chan []byte, 1)
		upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			authFrames <- data
			conn.WriteMessage(websocket.TextMessage, []byte(authOK))
			conn.ReadMessage() // hold the connection until the client hangs up
		}))
		defer server.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sess, err := DialPairSession(ctx, server.URL, "test-jwt", "", true)
		if err != nil {
			t.Fatalf("DialPairSession() error: %v", err)
		}
		defer sess.Close()

		var authMsg struct {
			Type  string `json:"type"`
			Token string `json:"token"`
		}
		if err := json.Unmarshal(<-authFrames, &authMsg); err != nil {
			t.Fatalf("auth frame is not JSON: %v", err)
		}
		if authMsg.Type != "auth" || authMsg.Token != "test-jwt" {
			t.Errorf("auth frame = %+v, want type auth with token test-jwt", authMsg)
		}
	})

	receiveTests := []struct {
		name   string
		frames []string
	}{
		{"after the auth reply", []string{authOK, pairComplete}},
		{"before the auth reply", []string{pairComplete, authOK}},
		{"skipping other frames", []string{`not json`, authOK, `{"type":"presence_ack"}`, `{"type":"pair_result","ok":true}`, pairComplete}},
	}
	for _, tt := range receiveTests {
		t.Run("receives pair_complete "+tt.name, func(t *testing.T) {
			msg, err := dialAndWait(t, pairServer(t, sendFrames(tt.frames...)), 5*time.Second)
			if err != nil {
				t.Fatalf("WaitForPairComplete() error: %v", err)
			}
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
	}

	errorTests := []struct {
		name    string
		serve   func(*websocket.Conn)
		wantErr string
	}{
		{
			name:    "times out when no pair_complete received",
			serve:   sendFrames(authOK),
			wantErr: "pairing timed out",
		},
		{
			name:    "times out when the server never answers auth",
			serve:   func(*websocket.Conn) {},
			wantErr: "read auth response",
		},
		{
			name:    "fails on WebSocket auth error",
			serve:   sendFrames(`{"type":"error","error":"Invalid token\u001b]0;pwn\u0007"}`),
			wantErr: "WebSocket auth failed: Invalid token",
		},
		{
			name:    "rejects invalid MobileDeviceID format",
			serve:   sendFrames(authOK, `{"type":"pair_complete","mobileDeviceId":"INVALID-ID!","mobileX25519PublicKey":"key=="}`),
			wantErr: "invalid device ID",
		},
		{
			name: "rejects oversized message",
			serve: func(conn *websocket.Conn) {
				conn.WriteMessage(websocket.TextMessage, []byte(authOK))
				conn.WriteMessage(websocket.TextMessage, make([]byte, maxPairMessageSize+1))
			},
			wantErr: "read limit",
		},
		{
			name: "sanitizes server close reason after auth",
			serve: func(conn *websocket.Conn) {
				conn.WriteMessage(websocket.TextMessage, []byte(authOK))
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "bad\x1b]0;pwn\x07"))
			},
			wantErr: "read WebSocket message",
		},
		{
			name: "sanitizes server close reason during auth",
			serve: func(conn *websocket.Conn) {
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "bad\x1b]0;pwn\x07"))
			},
			wantErr: "read auth response",
		},
	}
	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			start := time.Now()
			_, err := dialAndWait(t, pairServer(t, tt.serve), 300*time.Millisecond)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
			if strings.ContainsAny(err.Error(), "\x1b\x07") {
				t.Errorf("error %q contains control characters", err.Error())
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("took %v, want the context deadline to bound it", elapsed)
			}
		})
	}

	t.Run("sends presence while waiting", func(t *testing.T) {
		server := pairServer(t, func(conn *websocket.Conn) {
			conn.WriteMessage(websocket.TextMessage, []byte(authOK))
			// Deliver pair_complete only once the host has sent presence.
			for {
				_, data, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if string(data) == `{"type":"presence"}` {
					break
				}
			}
			conn.WriteMessage(websocket.TextMessage, []byte(pairComplete))
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sess, err := DialPairSession(ctx, server.URL, "test-jwt", "", true)
		if err != nil {
			t.Fatalf("DialPairSession() error: %v", err)
		}
		defer sess.Close()
		sess.keepaliveInterval = 10 * time.Millisecond

		msg, err := sess.WaitForPairComplete(ctx)
		if err != nil {
			t.Fatalf("WaitForPairComplete() error: %v", err)
		}
		if msg.MobileDeviceID != "bb22cc33dd44ee55ff66aa11bb22cc33" {
			t.Errorf("mobileDeviceId = %q, want %q", msg.MobileDeviceID, "bb22cc33dd44ee55ff66aa11bb22cc33")
		}
	})
}

func TestPairSession(t *testing.T) {
	const mobileID = "bb22cc33dd44ee55ff66aa11bb22cc33"

	// open runs a server that delivers pair_complete with mobileDeviceID,
	// forwards the host's next frame on the returned channel (closing it
	// instead if the host hangs up first), hands the connection to respond,
	// and holds it until the client hangs up. The session waits for
	// pair_complete before it is returned; validation errors are ignored.
	open := func(t *testing.T, confirm bool, mobileDeviceID string, respond func(*websocket.Conn)) (*PairSession, <-chan []byte) {
		t.Helper()
		decisions := make(chan []byte, 1)
		server := pairServer(t, func(conn *websocket.Conn) {
			conn.WriteMessage(websocket.TextMessage, []byte(authOK))
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"pair_complete","mobileDeviceId":"`+mobileDeviceID+`","mobileX25519PublicKey":"key=="}`))
			_, decision, err := conn.ReadMessage()
			if err != nil {
				close(decisions)
				return
			}
			decisions <- decision
			respond(conn)
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sess, err := DialPairSession(ctx, server.URL, "test-jwt", "", confirm)
		if err != nil {
			t.Fatalf("DialPairSession() error: %v", err)
		}
		sess.WaitForPairComplete(ctx)
		return sess, decisions
	}

	// nextFrame returns the host's frame after pair_complete, or nil if the
	// host hung up without one.
	nextFrame := func(t *testing.T, decisions <-chan []byte) []byte {
		t.Helper()
		select {
		case data := <-decisions:
			return data
		case <-time.After(5 * time.Second):
			t.Fatal("server saw neither a frame nor a hang-up")
			return nil
		}
	}

	// assertDecision checks the host's frame is exactly {type, mobileDeviceId}.
	assertDecision := func(t *testing.T, decisions <-chan []byte, wantType, wantID string) {
		t.Helper()
		data := nextFrame(t, decisions)
		if data == nil {
			t.Fatal("server received no decision frame")
		}
		var got map[string]any
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("decision frame %q is not JSON: %v", data, err)
		}
		if len(got) != 2 || got["type"] != wantType || got["mobileDeviceId"] != wantID {
			t.Errorf("decision frame = %s, want {type: %s, mobileDeviceId: %s}", data, wantType, wantID)
		}
	}

	acceptTests := []struct {
		name    string
		respond func(*websocket.Conn)
		timeout time.Duration
		wantErr []string // empty means Accept succeeds
	}{
		{
			name:    "confirmed",
			respond: sendFrames(`{"type":"pair_result","mobileDeviceId":"` + mobileID + `","ok":true}`),
		},
		{
			name: "skips unrelated frames",
			respond: sendFrames(
				`{"type":"presence_ack"}`,
				`not json`,
				`{"type":"pair_result","mobileDeviceId":"cc33dd44ee55ff66aa11bb22cc33dd44","ok":false}`,
				`{"type":"pair_result","mobileDeviceId":"`+mobileID+`","ok":true}`,
			),
		},
		{
			name:    "not committed",
			respond: sendFrames(`{"type":"pair_result","mobileDeviceId":"` + mobileID + `","ok":false}`),
			wantErr: []string{"server did not confirm the pairing (the mobile may have timed out)"},
		},
		{
			name:    "server error",
			respond: sendFrames(`{"type":"error","error":"Unknown message type: pair_accept\u001b]0;pwn\u0007"}`),
			wantErr: []string{"server refused pair_accept: Unknown message type: pair_accept"},
		},
		{
			name:    "no answer",
			respond: func(*websocket.Conn) {},
			timeout: 200 * time.Millisecond,
			wantErr: []string{"timeout", "pairing state is unknown", "run 'pmux pair' again"},
		},
		{
			name: "connection dropped",
			respond: func(conn *websocket.Conn) {
				conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "bye\x1b]0;pwn\x07"))
			},
			wantErr: []string{"pairing state is unknown", "run 'pmux pair' again"},
		},
	}
	for _, tt := range acceptTests {
		t.Run("Accept "+tt.name, func(t *testing.T) {
			sess, decisions := open(t, true, mobileID, tt.respond)
			defer sess.Close()
			timeout := tt.timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}

			start := time.Now()
			err := sess.Accept(timeout)
			elapsed := time.Since(start)
			assertDecision(t, decisions, "pair_accept", mobileID)
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("Accept() error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Accept() error = nil, want %q", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Accept() error = %q, want it to contain %q", err, want)
				}
			}
			if strings.ContainsAny(err.Error(), "\x1b\x07") {
				t.Errorf("error %q contains control characters", err.Error())
			}
			if elapsed > timeout+2*time.Second {
				t.Errorf("Accept took %v with timeout %v", elapsed, timeout)
			}
		})
	}

	t.Run("Reject", func(t *testing.T) {
		sess, decisions := open(t, true, mobileID, func(*websocket.Conn) {})
		defer sess.Close()
		if err := sess.Reject(); err != nil {
			t.Fatalf("Reject() error: %v", err)
		}
		assertDecision(t, decisions, "pair_reject", mobileID)
	})

	t.Run("Close rejects an unanswered pair_complete", func(t *testing.T) {
		sess, decisions := open(t, true, mobileID, func(*websocket.Conn) {})
		if err := sess.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
		assertDecision(t, decisions, "pair_reject", mobileID)
	})

	t.Run("Close rejects a pair_complete with an invalid device ID", func(t *testing.T) {
		const badID = "INVALID-ID!"
		sess, decisions := open(t, true, badID, func(*websocket.Conn) {})
		if err := sess.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
		assertDecision(t, decisions, "pair_reject", badID)
	})

	t.Run("Close sends nothing after Accept", func(t *testing.T) {
		frames := make(chan []byte, 1)
		sess, decisions := open(t, true, mobileID, func(conn *websocket.Conn) {
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"pair_result","mobileDeviceId":"`+mobileID+`","ok":false}`))
			_, data, err := conn.ReadMessage()
			if err != nil {
				data = nil
			}
			frames <- data
		})
		sess.Accept(5 * time.Second) //nolint:errcheck // the result is not under test
		assertDecision(t, decisions, "pair_accept", mobileID)
		if err := sess.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
		if data := <-frames; data != nil {
			t.Errorf("host sent %s after its decision, want nothing", data)
		}
	})

	t.Run("legacy session never sends a decision", func(t *testing.T) {
		sess, decisions := open(t, false, mobileID, func(*websocket.Conn) {})
		if err := sess.Accept(time.Second); err == nil {
			t.Error("Accept() on a legacy session should fail")
		}
		if err := sess.Reject(); err == nil {
			t.Error("Reject() on a legacy session should fail")
		}
		if err := sess.Close(); err != nil {
			t.Fatalf("Close() error: %v", err)
		}
		if data := nextFrame(t, decisions); data != nil {
			t.Errorf("legacy session sent %s, want nothing", data)
		}
	})
}
