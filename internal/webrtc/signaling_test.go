package webrtc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

// testSetup creates an identity and logger for tests.
func testSetup(t *testing.T) (*auth.Identity, *slog.Logger) {
	t.Helper()
	keysDir := t.TempDir()
	store := auth.NewMemorySecretStore()
	id, err := auth.GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return id, logger
}

// mockTokenServer returns a test server that issues fake tokens.
func mockTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt-token"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// mockWSServer creates a WebSocket server that handles auth + custom behavior.
func mockWSServer(t *testing.T, handler func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt-token"}`))
			return
		}
		if r.URL.Path == "/ws" {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				t.Logf("upgrade error: %v", err)
				return
			}
			defer conn.Close()
			handler(conn)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestSignalingClient_ConnectsAndAuthenticates(t *testing.T) {
	id, logger := testSetup(t)

	var authReceived atomic.Bool
	server := mockWSServer(t, func(conn *websocket.Conn) {
		// Read auth message
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg SignalingMessage
		json.Unmarshal(data, &msg)
		if msg.Type == "auth" && msg.Token == "test-jwt-token" {
			authReceived.Store(true)
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
		}

		// Keep connection open briefly for presence
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var received []SignalingMessage
	var mu sync.Mutex
	handler := func(msg SignalingMessage) {
		mu.Lock()
		received = append(received, msg)
		mu.Unlock()
	}

	sc := NewSignalingClient(id, server.URL, "", handler, logger, "")
	sc.HTTPClient = server.Client()

	// Run will exit when context cancels or connection drops
	sc.Run(ctx)

	if !authReceived.Load() {
		t.Error("server did not receive auth message with JWT")
	}
}

func TestSignalingClient_SendsPresenceHeartbeats(t *testing.T) {
	id, logger := testSetup(t)

	var presenceCount atomic.Int32
	server := mockWSServer(t, func(conn *websocket.Conn) {
		// Auth
		_, data, _ := conn.ReadMessage()
		var msg SignalingMessage
		json.Unmarshal(data, &msg)
		if msg.Type == "auth" {
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
		}

		// Read subsequent messages
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var msg SignalingMessage
			json.Unmarshal(data, &msg)
			if msg.Type == "presence" {
				presenceCount.Add(1)
			}
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()
	sc.PresenceInterval = 200 * time.Millisecond // fast for testing

	go sc.Run(ctx)

	// Wait enough for connection + multiple heartbeats
	time.Sleep(1500 * time.Millisecond)
	cancel()

	if presenceCount.Load() < 2 {
		t.Errorf("expected at least 2 presence heartbeats, got %d", presenceCount.Load())
	}
}

func TestSignalingClient_DispatchesMessages(t *testing.T) {
	id, logger := testSetup(t)

	server := mockWSServer(t, func(conn *websocket.Conn) {
		// Auth
		_, data, _ := conn.ReadMessage()
		var msg SignalingMessage
		json.Unmarshal(data, &msg)
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))

		// Send a connect_request to the agent
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"connect_request","targetDeviceId":"mobile-123"}`))

		// Send an SDP offer
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"sdp_offer","targetDeviceId":"mobile-123","sdp":"v=0..."}`))

		time.Sleep(500 * time.Millisecond)
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var received []SignalingMessage
	var mu sync.Mutex
	handler := func(msg SignalingMessage) {
		mu.Lock()
		received = append(received, msg)
		mu.Unlock()
	}

	sc := NewSignalingClient(id, server.URL, "", handler, logger, "")
	sc.HTTPClient = server.Client()

	sc.Run(ctx)

	mu.Lock()
	defer mu.Unlock()

	if len(received) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(received))
	}

	types := make(map[string]bool)
	for _, msg := range received {
		types[msg.Type] = true
	}

	if !types["connect_request"] {
		t.Error("did not receive connect_request message")
	}
	if !types["sdp_offer"] {
		t.Error("did not receive sdp_offer message")
	}
}

func TestSignalingClient_SendMessages(t *testing.T) {
	id, logger := testSetup(t)

	var serverReceived []SignalingMessage
	var mu sync.Mutex
	server := mockWSServer(t, func(conn *websocket.Conn) {
		// Auth
		_, data, _ := conn.ReadMessage()
		var msg SignalingMessage
		json.Unmarshal(data, &msg)
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))

		// Read remaining messages
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var msg SignalingMessage
			json.Unmarshal(data, &msg)
			mu.Lock()
			serverReceived = append(serverReceived, msg)
			mu.Unlock()
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	go sc.Run(ctx)
	time.Sleep(500 * time.Millisecond) // wait for connection

	// Send SDP offer
	err := sc.Send(SignalingMessage{
		Type:           "sdp_offer",
		TargetDeviceID: "mobile-456",
		SDP:            "v=0\r\n...",
	})
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	// Send ICE candidate
	idx := 0
	err = sc.Send(SignalingMessage{
		Type:           "ice_candidate",
		TargetDeviceID: "mobile-456",
		Candidate:      "candidate:...",
		SDPMid:         "0",
		SDPMLineIndex:  &idx,
	})
	if err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	time.Sleep(300 * time.Millisecond)
	cancel()

	mu.Lock()
	defer mu.Unlock()

	sdpFound := false
	iceFound := false
	for _, msg := range serverReceived {
		if msg.Type == "sdp_offer" && msg.SDP == "v=0\r\n..." {
			sdpFound = true
		}
		if msg.Type == "ice_candidate" && msg.Candidate == "candidate:..." {
			iceFound = true
		}
	}

	if !sdpFound {
		t.Error("server did not receive sdp_offer")
	}
	if !iceFound {
		t.Error("server did not receive ice_candidate")
	}
}

func TestSignalingClient_ReconnectsOnDisconnect(t *testing.T) {
	id, logger := testSetup(t)

	var connectCount atomic.Int32
	server := mockWSServer(t, func(conn *websocket.Conn) {
		count := connectCount.Add(1)

		// Auth
		_, data, _ := conn.ReadMessage()
		var msg SignalingMessage
		json.Unmarshal(data, &msg)
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))

		if count == 1 {
			// First connection: close immediately to trigger reconnect
			time.Sleep(100 * time.Millisecond)
			conn.Close()
			return
		}

		// Second connection: stay alive a bit
		time.Sleep(2 * time.Second)
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	sc.Run(ctx)

	if connectCount.Load() < 2 {
		t.Errorf("expected at least 2 connections (reconnect), got %d", connectCount.Load())
	}
}

func TestSignalingClient_AuthFailure(t *testing.T) {
	id, logger := testSetup(t)

	server := mockWSServer(t, func(conn *websocket.Conn) {
		// Auth
		conn.ReadMessage()
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","error":"Authentication failed"}`))
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	// Should keep trying to reconnect but always fail auth
	sc.Run(ctx)
	// If we get here without hanging, the test passes (context timeout)
}

func TestSignalingClient_SendWhenNotConnected(t *testing.T) {
	id, logger := testSetup(t)

	sc := NewSignalingClient(id, "http://localhost:1", "", nil, logger, "")

	err := sc.Send(SignalingMessage{Type: "presence"})
	if err == nil {
		t.Error("expected error when not connected, got nil")
	}
}

func TestSignalingClient_Close(t *testing.T) {
	id, logger := testSetup(t)

	server := mockWSServer(t, func(conn *websocket.Conn) {
		conn.ReadMessage() // auth
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
		time.Sleep(10 * time.Second) // keep alive
	})
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	done := make(chan struct{})
	go func() {
		sc.Run(ctx)
		close(done)
	}()

	time.Sleep(500 * time.Millisecond)

	// Close should trigger disconnect
	sc.Close()
	cancel()

	select {
	case <-done:
		// Success
	case <-time.After(3 * time.Second):
		t.Error("Run() did not return after Close()")
	}
}

func TestSignalingClient_ErrorMessagesLogged(t *testing.T) {
	id, logger := testSetup(t)

	server := mockWSServer(t, func(conn *websocket.Conn) {
		conn.ReadMessage() // auth
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))

		// Send an error message
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","error":"device not found"}`))

		time.Sleep(300 * time.Millisecond)
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var received []SignalingMessage
	var mu sync.Mutex
	handler := func(msg SignalingMessage) {
		mu.Lock()
		received = append(received, msg)
		mu.Unlock()
	}

	sc := NewSignalingClient(id, server.URL, "", handler, logger, "")
	sc.HTTPClient = server.Client()

	sc.Run(ctx)

	mu.Lock()
	defer mu.Unlock()

	// Error messages should NOT be dispatched to handler
	for _, msg := range received {
		if msg.Type == "error" {
			t.Error("error messages should not be dispatched to handler")
		}
	}
}

func TestSignalingClient_SendsNameInAuth(t *testing.T) {
	id, logger := testSetup(t)

	var receivedName atomic.Value
	server := mockWSServer(t, func(conn *websocket.Conn) {
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg SignalingMessage
		json.Unmarshal(data, &msg)
		if msg.Type == "auth" {
			receivedName.Store(msg.Name)
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
		}
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "my-workstation", nil, logger, "")
	sc.HTTPClient = server.Client()

	sc.Run(ctx)

	name, ok := receivedName.Load().(string)
	if !ok || name != "my-workstation" {
		t.Errorf("expected auth message name=%q, got %q", "my-workstation", name)
	}
}

func TestSignalActivity_WakeFromDormancy(t *testing.T) {
	id, logger := testSetup(t)

	// Set up a server that stays connected long enough for us to observe behaviour.
	server := mockWSServer(t, func(conn *websocket.Conn) {
		conn.ReadMessage() // auth
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
		// Stay alive so the connection doesn't drop during the test.
		time.Sleep(3 * time.Second)
	})
	defer server.Close()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	// Place the client in dormancy directly — same package, fields are accessible.
	sc.mu.Lock()
	sc.dormant = true
	sc.failureStart = time.Now().Add(-DormancyTimeout - time.Second)
	sc.mu.Unlock()

	// Verify dormant before signal.
	sc.mu.Lock()
	dormantBefore := sc.dormant
	sc.mu.Unlock()
	if !dormantBefore {
		t.Fatal("expected client to be dormant before SignalActivity()")
	}

	// Run in background — it will block on dormancy until signalled.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		sc.Run(ctx)
		close(done)
	}()

	// Give Run() a moment to enter the dormancy wait branch.
	time.Sleep(50 * time.Millisecond)

	// Send activity signal.
	sc.SignalActivity()

	// Wait briefly for Run() to process the signal and clear dormancy.
	time.Sleep(300 * time.Millisecond)

	sc.mu.Lock()
	dormantAfter := sc.dormant
	sc.mu.Unlock()

	if dormantAfter {
		t.Error("expected dormant=false after SignalActivity(), still dormant")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("Run() did not return after context cancel")
	}
}

func TestJWT_ReturnsCurrentToken(t *testing.T) {
	id, logger := testSetup(t)

	server := mockWSServer(t, func(conn *websocket.Conn) {
		conn.ReadMessage() // auth
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
		time.Sleep(2 * time.Second)
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	// JWT() should be empty before any auth.
	if got := sc.JWT(); got != "" {
		t.Errorf("expected empty JWT before auth, got %q", got)
	}

	done := make(chan struct{})
	go func() {
		sc.Run(ctx)
		close(done)
	}()

	// Wait for the auth flow to complete and token to be cached.
	time.Sleep(400 * time.Millisecond)

	got := sc.JWT()
	if got != "test-jwt-token" {
		t.Errorf("JWT() = %q, want %q", got, "test-jwt-token")
	}

	cancel()
	<-done
}

func TestTokenRefreshLoop_RefreshesToken(t *testing.T) {
	id, logger := testSetup(t)

	var tokenCallCount atomic.Int32

	// Build a custom server that counts /auth/token calls and keeps WS alive.
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			tokenCallCount.Add(1)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt-token"}`))
			return
		}
		if r.URL.Path == "/ws" {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.ReadMessage() // auth
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
			// Stay connected for the duration of the test.
			time.Sleep(5 * time.Second)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	done := make(chan struct{})
	go func() {
		sc.Run(ctx)
		close(done)
	}()

	// Wait for the initial connection + auth (one token call).
	time.Sleep(300 * time.Millisecond)

	// Force jwtExpiry into the past so tokenRefreshLoop will see needsRefresh=true
	// on its next tick.
	sc.mu.Lock()
	sc.jwtExpiry = time.Now().Add(-time.Hour)
	sc.mu.Unlock()

	// tokenRefreshLoop polls every 30s, which is too slow to wait for.
	// Instead, directly call ensureToken() to simulate what the loop does —
	// this proves the refresh path works and increments the server counter.
	initialCount := tokenCallCount.Load()
	if err := sc.ensureToken(); err != nil {
		t.Fatalf("ensureToken() after forcing expiry: %v", err)
	}

	afterCount := tokenCallCount.Load()
	if afterCount <= initialCount {
		t.Errorf("expected token endpoint to be called again after expiry, count stayed at %d", initialCount)
	}

	cancel()
	<-done
}

func TestTokenRefreshLoop_ServerError(t *testing.T) {
	id, logger := testSetup(t)

	var tokenCallCount atomic.Int32

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			count := tokenCallCount.Add(1)
			// First call succeeds so the client can connect; subsequent calls fail.
			if count == 1 {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"token":"test-jwt-token"}`))
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"internal server error"}`))
			}
			return
		}
		if r.URL.Path == "/ws" {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			conn.ReadMessage() // auth
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
			time.Sleep(3 * time.Second)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	done := make(chan struct{})
	go func() {
		sc.Run(ctx)
		close(done)
	}()

	// Wait for initial connection.
	time.Sleep(300 * time.Millisecond)

	// Force token expiry and call ensureToken() — simulates what the refresh
	// loop does, and the server will now return 500.
	sc.mu.Lock()
	sc.jwtExpiry = time.Now().Add(-time.Hour)
	sc.mu.Unlock()

	err := sc.ensureToken()
	if err == nil {
		t.Error("expected error from ensureToken() when server returns 500, got nil")
	}

	// Client should still be running (not panicked, not exited).
	select {
	case <-done:
		t.Error("Run() exited unexpectedly after token server error")
	default:
		// Still running — correct.
	}

	cancel()
	<-done
}

func TestReconnect_IncreasesBackoff(t *testing.T) {
	id, logger := testSetup(t)

	// Use a server that rejects WebSocket auth with an error response so that
	// connectAndServe returns (false, err) on every attempt. That keeps the
	// backoff variable growing rather than resetting on each cycle.
	attemptTimes := make([]time.Time, 0, 6)
	var timeMu sync.Mutex

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt-token"}`))
			return
		}
		if r.URL.Path == "/ws" {
			conn, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			timeMu.Lock()
			attemptTimes = append(attemptTimes, time.Now())
			timeMu.Unlock()
			// Read the auth message then immediately respond with an error.
			// This makes connectAndServe return (false, err), so backoff grows.
			conn.ReadMessage()
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","error":"auth rejected"}`))
			conn.Close()
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Enough time for: attempt 1 + 1s backoff + attempt 2 + 2s backoff + attempt 3.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	sc.Run(ctx)

	timeMu.Lock()
	times := attemptTimes
	timeMu.Unlock()

	if len(times) < 3 {
		t.Fatalf("expected at least 3 connection attempts to observe backoff, got %d", len(times))
	}

	// Gap between attempt 1→2 must be ≥ initialBackoff (1s).
	// Gap between attempt 2→3 must be ≥ 2×initialBackoff (2s).
	gap1 := times[1].Sub(times[0])
	gap2 := times[2].Sub(times[1])

	if gap1 < initialBackoff {
		t.Errorf("gap between attempt 1 and 2 = %v, want >= %v (initialBackoff)", gap1, initialBackoff)
	}
	if gap2 < time.Duration(float64(initialBackoff)*backoffFactor) {
		t.Errorf("gap between attempt 2 and 3 = %v, want >= %v (2×initialBackoff)", gap2,
			time.Duration(float64(initialBackoff)*backoffFactor))
	}
}

func TestSignalingClient_SendWritesJSON(t *testing.T) {
	id, logger := testSetup(t)

	type capture struct {
		msg SignalingMessage
		raw []byte
	}
	var received []capture
	var mu sync.Mutex

	server := mockWSServer(t, func(conn *websocket.Conn) {
		conn.ReadMessage() // auth
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))

		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var msg SignalingMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue
			}
			mu.Lock()
			received = append(received, capture{msg: msg, raw: data})
			mu.Unlock()
		}
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	go sc.Run(ctx)
	time.Sleep(400 * time.Millisecond) // wait for connection

	mlineIdx := 1
	want := SignalingMessage{
		Type:           "ice_candidate",
		TargetDeviceID: "mobile-test-999",
		Candidate:      "candidate:abc def",
		SDPMid:         "audio",
		SDPMLineIndex:  &mlineIdx,
	}

	if err := sc.Send(want); err != nil {
		t.Fatalf("Send() error: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	cancel()

	mu.Lock()
	defer mu.Unlock()

	// Find the ice_candidate message (skip presence heartbeats).
	var got *SignalingMessage
	for i := range received {
		if received[i].msg.Type == "ice_candidate" {
			got = &received[i].msg
			break
		}
	}

	if got == nil {
		t.Fatal("server did not receive ice_candidate message")
	}
	if got.TargetDeviceID != want.TargetDeviceID {
		t.Errorf("TargetDeviceID = %q, want %q", got.TargetDeviceID, want.TargetDeviceID)
	}
	if got.Candidate != want.Candidate {
		t.Errorf("Candidate = %q, want %q", got.Candidate, want.Candidate)
	}
	if got.SDPMid != want.SDPMid {
		t.Errorf("SDPMid = %q, want %q", got.SDPMid, want.SDPMid)
	}
	if got.SDPMLineIndex == nil || *got.SDPMLineIndex != mlineIdx {
		t.Errorf("SDPMLineIndex = %v, want %d", got.SDPMLineIndex, mlineIdx)
	}
}

func TestReadDeadline_DisconnectsOnSilentServer(t *testing.T) {
	id, logger := testSetup(t)

	// Track how many times the server accepts a WebSocket connection.
	var connectCount atomic.Int32

	server := mockWSServer(t, func(conn *websocket.Conn) {
		count := connectCount.Add(1)

		// Authenticate normally.
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg SignalingMessage
		json.Unmarshal(data, &msg)
		if msg.Type == "auth" {
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`))
		}

		if count == 1 {
			// First connection: go completely silent — send nothing, read
			// nothing. The client's read deadline should fire and cause a
			// reconnect rather than blocking forever.
			time.Sleep(5 * time.Second)
			return
		}

		// Second connection: stay alive briefly so the test can observe
		// the reconnect happened, then close.
		time.Sleep(1 * time.Second)
		conn.Close()
	})
	defer server.Close()

	// Use short PresenceInterval + grace so the read deadline
	// (2*500ms + 200ms = 1.2s) fires quickly, keeping the test fast.
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	sc := NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()
	sc.PresenceInterval = 500 * time.Millisecond
	sc.ReadDeadlineGrace = 200 * time.Millisecond // read deadline = 1.2s

	done := make(chan struct{})
	go func() {
		sc.Run(ctx)
		close(done)
	}()

	// Wait long enough for the first connection to time out and a
	// reconnect to occur (1.2s deadline + 1s backoff + second auth).
	time.Sleep(5 * time.Second)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run() did not return after context cancel")
	}

	if connectCount.Load() < 2 {
		t.Errorf("expected at least 2 connections (reconnect after read deadline), got %d", connectCount.Load())
	}
}
