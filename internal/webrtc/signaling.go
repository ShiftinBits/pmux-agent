// Package webrtc manages Pion RTCPeerConnection, DataChannel, and signaling.
package webrtc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/shiftinbits/pmux-agent/internal/auth"
)

const (
	// maxSignalingMessageSize bounds a single inbound signaling WebSocket
	// frame so a hostile or compromised server cannot exhaust agent memory.
	maxSignalingMessageSize = 128 << 10

	// DefaultPresenceInterval is how often the agent sends presence heartbeats.
	DefaultPresenceInterval = 30 * time.Second

	// DefaultReadDeadlineGrace is the fixed grace period added on top of
	// 2×PresenceInterval when computing the WebSocket read deadline.
	DefaultReadDeadlineGrace = 10 * time.Second

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

	// connectCycleTimeout bounds one connection attempt: token exchange, WebSocket
	// dial and authentication share this single budget.
	connectCycleTimeout = 20 * time.Second
)

// stableConnectionThreshold is how long an authenticated connection must stay
// up before Run treats it as healthy and resets reconnect backoff. A server
// that accepts auth and then drops the socket must not pin backoff at its
// initial value. A var so tests can shorten it.
var stableConnectionThreshold = 30 * time.Second

// errAuthRejected marks a WebSocket auth the server explicitly refused (an
// error reply or a 4001 close), as opposed to a timeout or transport failure.
var errAuthRejected = errors.New("auth failed")

// jitter returns d scaled by a random factor in [1, 1.5] so agents retrying
// after a shared server outage don't reconnect in lockstep. The result is
// deliberately not capped at maxBackoff: capping would re-synchronize every
// agent at exactly maxBackoff.
func jitter(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int64N(int64(d)/2+1))
}

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
	AttemptID      string `json:"attemptId,omitempty"`

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

	// InitialBackoff controls the starting reconnection backoff delay.
	// Defaults to 1s if zero.
	InitialBackoff time.Duration

	// ReadDeadlineGrace is the fixed grace added to 2×PresenceInterval for
	// the rolling WebSocket read deadline. Defaults to 10s.
	ReadDeadlineGrace time.Duration

	mu        sync.Mutex
	conn      *websocket.Conn
	jwt       string
	jwtExpiry time.Time
	closed    bool

	// Dormancy: after DormancyTimeout of continuous reconnection failures,
	// stop retrying until an activity signal is received.
	failureStart time.Time // when continuous failures began (zero if not failing)
	dormant      bool      // true when in dormancy mode

	// suspended is set while the host is sleeping. The run loop pauses
	// reconnection (so the host does not re-register as online during the brief
	// pre-suspend window) until Resume clears it. See Suspend/Resume.
	suspended bool

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
		identity:          identity,
		serverURL:         strings.TrimRight(serverURL, "/"),
		handler:           handler,
		logger:            logger,
		hmacSecret:        hmacSecret,
		hostName:          hostName,
		PresenceInterval:  DefaultPresenceInterval,
		ReadDeadlineGrace: DefaultReadDeadlineGrace,
		activitySignal:    make(chan struct{}, 1),
		HTTPClient:        &http.Client{Timeout: 10 * time.Second},
	}
}

// readTimeout returns the rolling read deadline duration:
// 2×PresenceInterval + ReadDeadlineGrace (default 70s).
func (sc *SignalingClient) readTimeout() time.Duration {
	return 2*sc.PresenceInterval + sc.ReadDeadlineGrace
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
	startBackoff := initialBackoff
	if sc.InitialBackoff > 0 {
		startBackoff = sc.InitialBackoff
	}
	backoff := startBackoff

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
				backoff = startBackoff
				sc.logger.Info("activity signal received, resuming reconnection")
			}
		}

		// Suspend check: while the host is sleeping, pause reconnection entirely
		// so the agent does not re-register as online before the OS freezes it.
		// Resume sends an activity signal to wake this wait.
		sc.mu.Lock()
		isSuspended := sc.suspended
		sc.mu.Unlock()
		if isSuspended {
			sc.logger.Info("signaling suspended (host sleeping), waiting for resume")
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-sc.activitySignal:
				// Like any wake, resume grants a fresh retry window: failures
				// from before the sleep must not send the first probe after
				// it (often while the network is still coming up) to dormancy.
				sc.mu.Lock()
				sc.failureStart = time.Time{}
				sc.mu.Unlock()
				backoff = startBackoff
			}
			continue
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
			backoff = startBackoff
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

		// Wait with jittered exponential backoff before reconnecting. Jitter
		// applies to the wait only so it doesn't compound into backoff growth.
		wait := jitter(backoff)
		backoffStart := time.Now()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sc.activitySignal:
			// Activity signal received during backoff — reset and try immediately.
			// A wake grants a fresh retry window, so one failed probe while the
			// network is still coming up does not send the client straight back
			// to dormancy.
			sc.mu.Lock()
			sc.dormant = false
			sc.failureStart = time.Time{}
			sc.mu.Unlock()
			backoff = startBackoff
			sc.logger.Info("activity signal received during backoff, reconnecting immediately")
			continue
		case <-time.After(wait):
		}

		sc.logger.Info("reconnecting to signaling server", "backoff", backoff, "wait", wait)
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

// Suspend marks the host as going to sleep: it gracefully closes the current
// signaling connection (sending a WebSocket close frame, which the server turns
// into an immediate host_offline) and pauses reconnection until Resume is
// called. This makes the host's offline status accurate the instant it sleeps,
// rather than waiting for the server's idle timeout. No-op if already shut down.
//
// Unlike Close, this does not permanently shut the client down — the run loop
// stays alive, paused, ready to reconnect when Resume fires.
func (sc *SignalingClient) Suspend() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.closed {
		return
	}
	sc.suspended = true

	if sc.conn != nil {
		// Bound the write: this runs inside logind's pre-suspend "delay" window
		// (InhibitDelayMaxSec, default 5s), so a hung socket must not consume the
		// whole budget before the suspend proceeds.
		sc.conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		sc.conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		sc.conn.Close()
	}
}

// Resume clears the suspended state and wakes the run loop so the agent
// reconnects and re-registers presence after the host wakes from sleep.
// Safe to call from any goroutine; a no-op if not currently suspended.
func (sc *SignalingClient) Resume() {
	sc.mu.Lock()
	sc.suspended = false
	sc.mu.Unlock()
	sc.SignalActivity()
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
		_ = sc.conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(2*time.Second))
		sc.conn.Close()
	}
}

// connectAndServe establishes one WebSocket connection and runs until disconnect.
// Returns (true, err) if the authenticated connection stayed up at least
// stableConnectionThreshold, (false, err) otherwise.
func (sc *SignalingClient) connectAndServe(ctx context.Context) (connected bool, err error) {
	deadline := time.Now().Add(connectCycleTimeout)
	cycleCtx, cancelCycle := context.WithDeadline(ctx, deadline)
	defer cancelCycle()

	// Ensure we have a valid JWT. The exchange shares the cycle budget with the
	// dial and authentication below.
	if err := sc.ensureToken(cycleCtx); err != nil {
		return false, fmt.Errorf("obtain JWT: %w", err)
	}

	// Connect WebSocket
	wsURL := sc.serverURL + "/ws"
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

	dialer := &websocket.Dialer{
		Proxy: http.ProxyFromEnvironment,
	}
	conn, resp, err := dialer.DialContext(cycleCtx, wsURL, auth.SignWebSocketHeaders(wsURL, sc.hmacSecret))
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

	conn.SetReadLimit(maxSignalingMessageSize)

	defer func() {
		conn.Close()
		sc.mu.Lock()
		sc.conn = nil
		sc.mu.Unlock()
	}()

	// Authenticate before exposing conn to Send()/Close(). conn isn't reachable
	// by Close/Suspend yet, so close it on cancel to unblock the auth read.
	stopAuthWatch := context.AfterFunc(ctx, func() { conn.Close() })
	authErr := sc.authenticate(conn, deadline)
	stopAuthWatch()
	if authErr != nil {
		// Invalidate the cached JWT only when the server rejected it, so the
		// next attempt exchanges a fresh one. A timeout or transport error
		// keeps it: re-exchanging on a slow link would just eat the next
		// cycle's budget too.
		if errors.Is(authErr, errAuthRejected) {
			sc.mu.Lock()
			sc.jwtExpiry = time.Time{}
			sc.mu.Unlock()
		}
		return false, authErr
	}

	// Now authenticated — make visible to other goroutines.
	sc.mu.Lock()
	sc.conn = conn
	sc.mu.Unlock()
	connectedAt := time.Now()

	// Reset read deadline on WebSocket pong frames so server-level
	// pings prevent false timeout disconnects.
	readTimeout := sc.readTimeout()
	conn.SetPongHandler(func(appData string) error {
		return conn.SetReadDeadline(time.Now().Add(readTimeout))
	})

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
	readDone := make(chan struct{})
	go func() {
		<-presenceCtx.Done()
		select {
		case <-readDone:
			// The read loop already failed, so the connection is dead or
			// half-open; a close frame would only wait out its write deadline.
			conn.Close()
			return
		default:
		}
		if ctx.Err() != nil {
			// Shutdown: send a close frame so the server sees a clean 1000
			// close (and reports host_offline) rather than an abnormal drop.
			// WriteControl may run concurrently with the writes presenceLoop
			// and Send make under sc.mu, so no lock is needed here.
			_ = conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(2*time.Second))
		}
		conn.Close()
	}()

	// Read messages
	err = sc.readLoop(conn)
	close(readDone)
	return time.Since(connectedAt) >= stableConnectionThreshold, err
}

// authenticate sends the JWT auth message and waits for confirmation.
func (sc *SignalingClient) authenticate(conn *websocket.Conn, deadline time.Time) error {
	sc.mu.Lock()
	jwt := sc.jwt
	sc.mu.Unlock()

	authMsg := SignalingMessage{Type: "auth", Token: jwt, Name: sc.hostName}
	data, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("marshal auth message: %w", err)
	}

	conn.SetWriteDeadline(deadline)
	if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return fmt.Errorf("send auth message: %w", err)
	}
	conn.SetWriteDeadline(time.Time{}) // clear deadline

	// Wait for auth response
	conn.SetReadDeadline(deadline)
	_, respData, err := conn.ReadMessage()
	conn.SetReadDeadline(time.Time{}) // clear deadline

	if err != nil {
		if websocket.IsCloseError(err, 4001) {
			return fmt.Errorf("%w: %v", errAuthRejected, err)
		}
		return fmt.Errorf("read auth response: %w", err)
	}

	var resp SignalingMessage
	if err := json.Unmarshal(respData, &resp); err != nil {
		return fmt.Errorf("parse auth response: %w", err)
	}

	if resp.Type == "error" {
		return fmt.Errorf("%w: %s", errAuthRejected, resp.Error)
	}

	return nil
}

// parseJWTExpiry extracts the "exp" claim from a JWT without full validation.
// Returns a zero time if parsing fails (caller falls back to estimated expiry).
func parseJWTExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}
	}
	return time.Unix(claims.Exp, 0)
}

// ensureToken obtains or refreshes the JWT if needed. The exchange is bound to
// ctx and runs without sc.mu held, so a slow token endpoint never blocks Send,
// Suspend or Close.
func (sc *SignalingClient) ensureToken(ctx context.Context) error {
	sc.mu.Lock()
	if sc.jwt != "" && time.Until(sc.jwtExpiry) > TokenRefreshMargin {
		sc.logger.Debug("using cached JWT", "expiresIn", time.Until(sc.jwtExpiry).Round(time.Second))
		sc.mu.Unlock()
		return nil
	}
	sc.mu.Unlock()

	sc.logger.Info("exchanging new JWT")
	token, err := auth.ExchangeTokenContext(ctx, sc.identity, sc.serverURL, sc.HTTPClient, sc.hmacSecret)
	if err != nil {
		return err
	}

	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.jwt = token
	if exp := parseJWTExpiry(token); !exp.IsZero() {
		sc.jwtExpiry = exp
	} else {
		sc.jwtExpiry = time.Now().Add(JWTLifetime) // fallback to estimated expiry
	}
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
			// Bound the write: without a deadline a hung socket blocks this
			// goroutine while it holds sc.mu, which would also stall Suspend()
			// and Close() (they need the same lock) past the logind delay window.
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err = conn.WriteMessage(websocket.TextMessage, data)
			// Send a WebSocket-level PING so the server's automatic PONG
			// response resets our read deadline via the PongHandler. This
			// keeps the connection alive even if the server doesn't send
			// application-level responses to presence heartbeats.
			if err == nil {
				err = conn.WriteControl(
					websocket.PingMessage, nil, time.Now().Add(5*time.Second),
				)
			}
			conn.SetWriteDeadline(time.Time{}) // clear for the next iteration
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

		if err := sc.ensureToken(ctx); err != nil {
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
//
// A rolling read deadline is set before each ReadMessage call so that
// half-open connections (server dies without TCP close, NAT expiry) are
// detected within a bounded time instead of blocking forever.
func (sc *SignalingClient) readLoop(conn *websocket.Conn) error {
	readTimeout := sc.readTimeout()
	for {
		conn.SetReadDeadline(time.Now().Add(readTimeout))
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
