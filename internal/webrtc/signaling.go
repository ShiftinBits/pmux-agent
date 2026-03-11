// Package webrtc manages Pion RTCPeerConnection, DataChannel, and signaling.
package webrtc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

const (
	// DefaultPresenceInterval is how often the agent sends presence heartbeats.
	DefaultPresenceInterval = 30 * time.Second

	// TokenRefreshMargin is how early before expiry to refresh the JWT.
	TokenRefreshMargin = 5 * time.Minute

	// JWTLifetime is the expected JWT lifetime (matching server-issued 1hr tokens).
	JWTLifetime = 1 * time.Hour

	// Reconnection backoff parameters.
	initialBackoff = 1 * time.Second
	maxBackoff     = 30 * time.Second
	backoffFactor  = 2.0

	// DormancyTimeout is how long continuous reconnection failures must persist
	// before the signaling client enters dormancy (stops retrying).
	DormancyTimeout = 5 * time.Minute
)

// SignalingMessage represents a JSON message to/from the signaling server.
type SignalingMessage struct {
	Type           string `json:"type"`
	Token          string `json:"token,omitempty"`
	Name           string `json:"name,omitempty"`
	Status         string `json:"status,omitempty"`
	Error          string `json:"error,omitempty"`
	Reason         string `json:"reason,omitempty"`
	TargetDeviceID string `json:"targetDeviceId,omitempty"`
	DeviceID       string `json:"deviceId,omitempty"`

	// SDP fields
	SDP string `json:"sdp,omitempty"`

	// ICE candidate fields
	Candidate     string `json:"candidate,omitempty"`
	SDPMid        string `json:"sdpMid,omitempty"`
	SDPMLineIndex *int   `json:"sdpMLineIndex,omitempty"`
}

// MessageHandler is called when the signaling client receives a message.
// Only called for authenticated, non-error messages.
type MessageHandler func(msg SignalingMessage)

// SignalingClient manages a persistent WebSocket connection to the signaling server.
type SignalingClient struct {
	identity   *auth.Identity
	serverURL  string
	logger     *slog.Logger
	handler    MessageHandler
	hmacSecret string

	// hostName is the host's display name sent in WebSocket auth messages.
	hostName string

	// PresenceInterval controls how often heartbeats are sent. Defaults to 30s.
	PresenceInterval time.Duration

	mu        sync.Mutex
	conn      *websocket.Conn
	jwt       string
	jwtExpiry time.Time
	closed    bool

	// Dormancy: after DormancyTimeout of continuous reconnection failures,
	// stop retrying until an activity signal is received.
	failureStart time.Time // when continuous failures began (zero if not failing)
	dormant      bool      // true when in dormancy mode

	// activitySignal wakes the client from dormancy. External callers (e.g.,
	// the supervisor detecting new tmux commands) send on this channel to
	// resume reconnection attempts.
	activitySignal chan struct{}

	// HTTPClient used for token exchange. Defaults to a 10s-timeout client.
	HTTPClient *http.Client
}

// NewSignalingClient creates a signaling client for the given identity and server.
func NewSignalingClient(identity *auth.Identity, serverURL string, hostName string, handler MessageHandler, logger *slog.Logger, hmacSecret string) *SignalingClient {
	return &SignalingClient{
		identity:         identity,
		serverURL:        strings.TrimRight(serverURL, "/"),
		handler:          handler,
		logger:           logger,
		hmacSecret:       hmacSecret,
		hostName:         hostName,
		PresenceInterval: DefaultPresenceInterval,
		activitySignal:   make(chan struct{}, 1),
		HTTPClient:       &http.Client{Timeout: 10 * time.Second},
	}
}

// SignalActivity wakes the signaling client from dormancy, causing it to
// resume reconnection attempts. Safe to call from any goroutine.
// Used by the supervisor when it detects tmux command activity.
func (sc *SignalingClient) SignalActivity() {
	select {
	case sc.activitySignal <- struct{}{}:
	default:
		// Already signaled, don't block
	}
}

// Run connects to the signaling server and maintains the connection with
// automatic reconnection and token refresh. Blocks until ctx is canceled.
//
// After DormancyTimeout of continuous reconnection failures, the client
// enters dormancy and stops retrying. It resumes when SignalActivity() is
// called (e.g., when a new tmux command triggers supervisor activity).
func (sc *SignalingClient) Run(ctx context.Context) error {
	backoff := initialBackoff

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Dormancy check: if in dormancy, wait for activity signal or context cancel.
		sc.mu.Lock()
		isDormant := sc.dormant
		sc.mu.Unlock()

		if isDormant {
			sc.logger.Info("signaling client dormant, waiting for activity signal")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-sc.activitySignal:
				sc.mu.Lock()
				sc.dormant = false
				sc.failureStart = time.Time{}
				sc.mu.Unlock()
				backoff = initialBackoff
				sc.logger.Info("activity signal received, resuming reconnection")
			}
		}

		connected, err := sc.connectAndServe(ctx)
		if err == nil || ctx.Err() != nil {
			// Context canceled — actual graceful shutdown.
			return ctx.Err()
		}

		// HMAC rejection is permanent — stop retrying immediately.
		var hmacErr *auth.HMACRejectedError
		if errors.As(err, &hmacErr) {
			sc.logger.Error("signaling server rejected agent credentials", "error", err)
			return err
		}

		// Reset backoff and failure tracking after a successful connection
		if connected {
			backoff = initialBackoff
			sc.mu.Lock()
			sc.failureStart = time.Time{}
			sc.mu.Unlock()
		} else {
			// Track continuous failure start
			sc.mu.Lock()
			if sc.failureStart.IsZero() {
				sc.failureStart = time.Now()
			}
			// Check if failures have persisted long enough to enter dormancy
			if time.Since(sc.failureStart) >= DormancyTimeout {
				sc.dormant = true
				sc.mu.Unlock()
				sc.logger.Warn("entering dormancy after continuous signaling failures",
					"duration", time.Since(sc.failureStart))
				continue // loop back to dormancy check
			}
			sc.mu.Unlock()
		}

		sc.logger.Warn("signaling connection lost", "error", err)

		// Wait with exponential backoff before reconnecting
		backoffStart := time.Now()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sc.activitySignal:
			// Activity signal received during backoff — reset and try immediately
			sc.mu.Lock()
			sc.failureStart = time.Time{}
			sc.dormant = false
			sc.mu.Unlock()
			backoff = initialBackoff
			sc.logger.Info("activity signal received during backoff, reconnecting immediately")
			continue
		case <-time.After(backoff):
		}

		sc.logger.Info("reconnecting to signaling server", "backoff", backoff)
		// Safety net: only increase backoff if monotonic elapsed time approximates
		// the intended wait. Protects against hypothetical runtime timer anomalies.
		if time.Since(backoffStart) >= backoff/2 {
			backoff = time.Duration(math.Min(float64(backoff)*backoffFactor, float64(maxBackoff)))
		}
	}
}

// Send sends a signaling message to the server. Thread-safe.
func (sc *SignalingClient) Send(msg SignalingMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal signaling message: %w", err)
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.conn == nil {
		return fmt.Errorf("not connected")
	}
	return sc.conn.WriteMessage(websocket.TextMessage, data)
}

// JWT returns the current JWT token. Thread-safe.
func (sc *SignalingClient) JWT() string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.jwt
}

// Close shuts down the signaling client.
func (sc *SignalingClient) Close() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.closed {
		return
	}
	sc.closed = true

	if sc.conn != nil {
		sc.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		sc.conn.Close()
	}
}

// connectAndServe establishes one WebSocket connection and runs until disconnect.
// Returns (true, err) if auth succeeded before the error, (false, err) otherwise.
func (sc *SignalingClient) connectAndServe(ctx context.Context) (connected bool, err error) {
	// Ensure we have a valid JWT
	if err := sc.ensureToken(); err != nil {
		return false, fmt.Errorf("obtain JWT: %w", err)
	}

	// Connect WebSocket
	wsURL := sc.serverURL + "/ws"
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

	dialer := websocket.DefaultDialer
	conn, resp, err := dialer.DialContext(ctx, wsURL, auth.SignWebSocketHeaders(wsURL, sc.hmacSecret))
	if err != nil {
		if resp != nil && resp.Body != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if hmacErr := auth.CheckHMACRejection(resp.StatusCode, body, sc.serverURL); hmacErr != nil {
				return false, hmacErr
			}
		}
		return false, fmt.Errorf("connect to signaling server: %w", err)
	}

	defer func() {
		conn.Close()
		sc.mu.Lock()
		sc.conn = nil
		sc.mu.Unlock()
	}()

	// Authenticate before exposing conn to Send()/Close().
	if err := sc.authenticate(conn); err != nil {
		// Invalidate cached JWT so the next reconnect attempt forces a
		// fresh token exchange instead of reusing a rejected token.
		sc.mu.Lock()
		sc.jwtExpiry = time.Time{}
		sc.mu.Unlock()
		return false, err
	}

	// Now authenticated — make visible to other goroutines.
	sc.mu.Lock()
	sc.conn = conn
	sc.mu.Unlock()

	sc.logger.Info("connected to signaling server")

	// Start presence heartbeat
	presenceCtx, presenceCancel := context.WithCancel(ctx)
	defer presenceCancel()

	go sc.presenceLoop(presenceCtx, conn)

	// Start token refresh loop
	go sc.tokenRefreshLoop(presenceCtx)

	// Close conn when context is canceled (or connection ends) to unblock readLoop.
	// Uses presenceCtx so this goroutine exits when connectAndServe returns,
	// preventing a goroutine leak if ctx outlives this connection.
	go func() {
		<-presenceCtx.Done()
		conn.Close()
	}()

	// Read messages
	return true, sc.readLoop(conn)
}

// authenticate sends the JWT auth message and waits for confirmation.
func (sc *SignalingClient) authenticate(conn *websocket.Conn) error {
	sc.mu.Lock()
	jwt := sc.jwt
	sc.mu.Unlock()

	authMsg := SignalingMessage{Type: "auth", Token: jwt, Name: sc.hostName}
	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("marshal auth message: %w", err)
	}

	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return fmt.Errorf("send auth message: %w", err)
	}
	conn.SetWriteDeadline(time.Time{}) // clear deadline

	// Wait for auth response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, respData, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{}) // clear deadline

	if err != nil {
		return fmt.Errorf("read auth response: %w", err)
	}

	var resp SignalingMessage
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("parse auth response: %w", err)
	}

	if resp.Type == "error" {
		return fmt.Errorf("auth failed: %s", resp.Error)
	}

	return nil
}

// ensureToken obtains or refreshes the JWT if needed.
func (sc *SignalingClient) ensureToken() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.jwt != "" && time.Until(sc.jwtExpiry) > TokenRefreshMargin {
		sc.logger.Debug("using cached JWT", "expiresIn", time.Until(sc.jwtExpiry).Round(time.Second))
		return nil
	}

	sc.logger.Info("exchanging new JWT")
	token, err := auth.ExchangeToken(sc.identity, sc.serverURL, sc.HTTPClient, sc.hmacSecret)
	if err != nil {
		return err
	}

	sc.jwt = token
	sc.jwtExpiry = time.Now().Add(JWTLifetime).Round(0) // strip monotonic for wall-clock comparison
	return nil
}

// presenceLoop sends periodic heartbeats to the signaling server.
func (sc *SignalingClient) presenceLoop(ctx context.Context, conn *websocket.Conn) {
	ticker := time.NewTicker(sc.PresenceInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			msg := SignalingMessage{Type: "presence"}
			data, err := json.Marshal(msg)
			if err != nil {
				sc.logger.Warn("marshal presence message failed", "error", err)
				continue
			}

			sc.mu.Lock()
			err = conn.WriteMessage(websocket.TextMessage, data)
			sc.mu.Unlock()

			if err != nil {
				sc.logger.Debug("presence send failed", "error", err)
				return
			}
		}
	}
}

// tokenRefreshLoop polls periodically to check if the JWT needs refreshing.
// Uses wall-clock time.Now() comparisons instead of monotonic time.After()
// to correctly detect expired tokens after system sleep/wake.
func (sc *SignalingClient) tokenRefreshLoop(ctx context.Context) {
	const (
		pollInterval  = 30 * time.Second
		minBackoff    = 1 * time.Minute
		maxRefBackoff = 15 * time.Minute
		backoffMul    = 2.0
	)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	failBackoff := time.Duration(0)
	var lastFailure time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// If in backoff, check if enough wall-clock time has passed.
		if failBackoff > 0 && time.Since(lastFailure) < failBackoff {
			continue
		}

		// Check if refresh is needed using wall-clock comparison.
		sc.mu.Lock()
		needsRefresh := sc.jwtExpiry.Before(time.Now().Add(TokenRefreshMargin))
		sc.mu.Unlock()

		if !needsRefresh {
			continue
		}

		if err := sc.ensureToken(); err != nil {
			sc.logger.Warn("failed to refresh JWT", "error", err)
			lastFailure = time.Now()
			if failBackoff == 0 {
				failBackoff = minBackoff
			} else {
				failBackoff = time.Duration(math.Min(
					float64(failBackoff)*backoffMul, float64(maxRefBackoff)))
			}
		} else {
			sc.logger.Debug("JWT refreshed")
			failBackoff = 0
		}
	}
}

// readLoop reads messages from the WebSocket and dispatches to the handler.
// The conn will be closed externally when context is canceled, unblocking ReadMessage.
func (sc *SignalingClient) readLoop(conn *websocket.Conn) error {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			// All read errors — including server-initiated normal closes
			// (1000/1001) — are treated as disconnections. The reconnection
			// loop in Run() will reconnect. The only true "graceful exit" is
			// context cancellation, which closes the conn from the outside.
			return fmt.Errorf("read signaling message: %w", err)
		}

		var msg SignalingMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			sc.logger.Debug("malformed signaling message", "error", err)
			continue
		}

		if msg.Type == "error" {
			sc.logger.Warn("signaling error", "error", msg.Error)
			continue
		}

		if sc.handler != nil {
			sc.handler(msg)
		}
	}
}
