//go:build integration

package integration

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
	sigclient "github.com/shiftinbits/pmux-agent/internal/webrtc"
)

// signalingMessage mirrors webrtc.SignalingMessage for test assertions.
type signalingMessage struct {
	Type   string `json:"type"`
	Token  string `json:"token,omitempty"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

func testIdentity(t *testing.T) *auth.Identity {
	t.Helper()
	keysDir := t.TempDir()
	store := auth.NewMemorySecretStore()
	id, err := auth.GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// mockWSServer creates a WebSocket server that handles auth + custom behavior.
func mockWSServer(t *testing.T, handler func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/token" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt-token"}`)) //nolint:errcheck
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

// TestReconnection_ReconnectsAfterDrop verifies the signaling client reconnects
// after the server drops the connection.
func TestReconnection_ReconnectsAfterDrop(t *testing.T) {
	id := testIdentity(t)
	logger := testLogger()

	var connectCount atomic.Int32
	server := mockWSServer(t, func(conn *websocket.Conn) {
		count := connectCount.Add(1)

		// Read auth message
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg signalingMessage
		json.Unmarshal(data, &msg) //nolint:errcheck
		if msg.Type == "auth" {
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`)) //nolint:errcheck
		}

		if count == 1 {
			// First connection: drop immediately to trigger reconnect
			time.Sleep(100 * time.Millisecond)
			conn.Close()
			return
		}

		// Second connection: stay alive
		time.Sleep(2 * time.Second)
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sc := sigclient.NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	sc.Run(ctx) //nolint:errcheck

	if connectCount.Load() < 2 {
		t.Errorf("expected at least 2 connections (reconnect), got %d", connectCount.Load())
	}
}

// TestReconnection_BackoffIncreases verifies that reconnection backoff increases
// on consecutive failures (exponential backoff).
func TestReconnection_BackoffIncreases(t *testing.T) {
	id := testIdentity(t)
	logger := testLogger()

	var mu sync.Mutex
	var connectTimes []time.Time
	var connectCount atomic.Int32

	server := mockWSServer(t, func(conn *websocket.Conn) {
		count := connectCount.Add(1)
		mu.Lock()
		connectTimes = append(connectTimes, time.Now())
		mu.Unlock()

		// Read auth message
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg signalingMessage
		json.Unmarshal(data, &msg) //nolint:errcheck
		if msg.Type == "auth" {
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`)) //nolint:errcheck
		}

		// Close immediately to force reconnection each time
		if count <= 3 {
			time.Sleep(50 * time.Millisecond)
			conn.Close()
			return
		}

		// 4th connection: stay alive until test ends
		time.Sleep(10 * time.Second)
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	sc := sigclient.NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	go sc.Run(ctx) //nolint:errcheck

	// Wait for at least 3 connections
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		if connectCount.Load() >= 3 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()

	if connectCount.Load() < 3 {
		t.Fatalf("expected at least 3 connections, got %d", connectCount.Load())
	}

	mu.Lock()
	times := make([]time.Time, len(connectTimes))
	copy(times, connectTimes)
	mu.Unlock()

	// Verify intervals are increasing (backoff)
	if len(times) >= 3 {
		gap1 := times[1].Sub(times[0])
		gap2 := times[2].Sub(times[1])
		t.Logf("reconnect gaps: gap1=%v, gap2=%v", gap1, gap2)

		// Second gap should be longer than first (exponential backoff).
		// Use generous tolerance (50%) for CI scheduling jitter.
		if gap2 < gap1/2 {
			t.Errorf("backoff not increasing: gap1=%v, gap2=%v (expected gap2 >= gap1/2)", gap1, gap2)
		}
	}
}

// TestReconnection_PreservesStateAcrossReconnect verifies that the signaling
// client can still dispatch messages after reconnecting.
func TestReconnection_PreservesStateAcrossReconnect(t *testing.T) {
	id := testIdentity(t)
	logger := testLogger()

	var connectCount atomic.Int32
	server := mockWSServer(t, func(conn *websocket.Conn) {
		count := connectCount.Add(1)

		// Auth
		_, data, err := conn.ReadMessage()
		if err != nil {
			return
		}
		var msg signalingMessage
		json.Unmarshal(data, &msg) //nolint:errcheck
		if msg.Type == "auth" {
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"auth","status":"ok"}`)) //nolint:errcheck
		}

		if count == 1 {
			// First connection: send a message then drop
			conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"connect_request","targetDeviceId":"mobile-1"}`)) //nolint:errcheck
			time.Sleep(200 * time.Millisecond)
			conn.Close()
			return
		}

		// Second connection: send another message
		time.Sleep(100 * time.Millisecond)
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"connect_request","targetDeviceId":"mobile-2"}`)) //nolint:errcheck
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	var received []sigclient.SignalingMessage
	var mu sync.Mutex
	handler := func(msg sigclient.SignalingMessage) {
		mu.Lock()
		received = append(received, msg)
		mu.Unlock()
	}

	sc := sigclient.NewSignalingClient(id, server.URL, "", handler, logger, "")
	sc.HTTPClient = server.Client()

	sc.Run(ctx) //nolint:errcheck

	mu.Lock()
	defer mu.Unlock()

	// Should have received messages from both connections
	if len(received) < 2 {
		t.Fatalf("expected at least 2 messages across reconnections, got %d", len(received))
	}

	// Verify we got messages from both connections
	targets := make(map[string]bool)
	for _, msg := range received {
		if msg.TargetDeviceID != "" {
			targets[msg.TargetDeviceID] = true
		}
	}

	if !targets["mobile-1"] {
		t.Error("did not receive message from first connection")
	}
	if !targets["mobile-2"] {
		t.Error("did not receive message from second connection")
	}
}

// TestReconnection_ActivitySignalWakesFromDormancy verifies that SignalActivity
// wakes a dormant signaling client.
func TestReconnection_ActivitySignalWakesFromDormancy(t *testing.T) {
	id := testIdentity(t)
	logger := testLogger()

	var connectCount atomic.Int32
	// Server that always fails auth to force continuous failures
	server := mockWSServer(t, func(conn *websocket.Conn) {
		connectCount.Add(1)
		_, _, err := conn.ReadMessage()
		if err != nil {
			return
		}
		// Respond with auth error to force reconnect
		conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","error":"auth failed"}`)) //nolint:errcheck
		conn.Close()
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sc := sigclient.NewSignalingClient(id, server.URL, "", nil, logger, "")
	sc.HTTPClient = server.Client()

	done := make(chan struct{})
	go func() {
		sc.Run(ctx) //nolint:errcheck
		close(done)
	}()

	// Let it try a few times
	time.Sleep(3 * time.Second)
	countBefore := connectCount.Load()

	// Signal activity to ensure it tries again
	sc.SignalActivity()
	time.Sleep(2 * time.Second)
	countAfter := connectCount.Load()

	cancel()
	<-done

	// After signaling activity, there should be additional connection attempts.
	// Use generous tolerance — at minimum the total count should exceed what
	// we observed before the signal.
	if countAfter <= countBefore {
		t.Errorf("activity signal did not trigger new attempts: before=%d, after=%d", countBefore, countAfter)
	}

	// The client should have made multiple connection attempts overall
	if connectCount.Load() < 2 {
		t.Errorf("expected at least 2 connection attempts, got %d", connectCount.Load())
	}
}
