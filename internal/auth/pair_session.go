package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// maxPairMessageSize bounds a single inbound pairing WebSocket message. It
// matches the agent's signaling limit (webrtc.maxSignalingMessageSize).
const maxPairMessageSize = 128 << 10

// connError extracts a clean message from Go's verbose network errors.
// "Post http://...: dial tcp ...: connect: connection refused" → "server unreachable (connection refused)"
func connError(err error) string {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Sprintf("cannot resolve server hostname %q", dnsErr.Name)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return "server connection timed out"
		}
		return fmt.Sprintf("server unreachable (%s)", opErr.Err)
	}
	return err.Error()
}

// serverError extracts a short error message from a non-200 HTTP response body.
// Tries JSON {"error":"..."} first, falls back to truncated raw body. The
// server-supplied text is passed through SanitizeDisplayString so callers can
// print the error to a terminal.
func serverError(statusCode int, body []byte) string {
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Error != "" {
		return fmt.Sprintf("server error (%d): %s", statusCode, SanitizeDisplayString(parsed.Error))
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return fmt.Sprintf("server error (%d): %s", statusCode, SanitizeDisplayString(msg))
}

// PairInitiateResponse is the server response from POST /auth/pair/initiate.
type PairInitiateResponse struct {
	PairingCode string `json:"pairingCode"`
	// PairConfirm is true only when the server echoes the request's
	// pairConfirm, i.e. it holds the mobile's request, for at most 30s, for
	// the host's pair_accept or pair_reject. A server without confirmed
	// pairing omits it and commits the pairing before the host sees
	// pair_complete.
	PairConfirm bool   `json:"pairConfirm"`
	Error       string `json:"error,omitempty"`
}

// PairCompleteMessage is the WebSocket message relayed when the mobile completes pairing.
type PairCompleteMessage struct {
	Type                  string `json:"type"`
	MobileDeviceID        string `json:"mobileDeviceId"`
	MobileX25519PublicKey string `json:"mobileX25519PublicKey"`
	MobileName            string `json:"mobileName,omitempty"`
	// PairMac is the mobile's HMAC over its X25519 key and device ID, keyed by the
	// QR-only pairing secret (see VerifyPairMAC). Empty from outdated apps.
	PairMac string `json:"pairMac"`
}

// InitiatePairing calls the server to create a pairing session.
// The name parameter is an optional human-readable host name sent to the server
// so it can be displayed on paired mobile devices.
func InitiatePairing(id *Identity, x25519PubKeyBase64 string, serverURL string, client *http.Client, name string, hmacSecret string) (*PairInitiateResponse, error) {
	nonce, err := fetchChallenge(id.DeviceID, serverURL, client, hmacSecret)
	if err != nil {
		return nil, err
	}
	signature := id.SignChallenge(id.DeviceID, nonce)

	reqBody := struct {
		DeviceID         string `json:"deviceId"`
		Ed25519PublicKey string `json:"ed25519PublicKey"`
		X25519PubKey     string `json:"x25519PublicKey"`
		Name             string `json:"name,omitempty"`
		Nonce            string `json:"nonce"`
		Signature        string `json:"signature"`
		// PairConfirm asks the server to hold the mobile's pairing request
		// for this host's pair_accept or pair_reject answer to pair_complete.
		PairConfirm bool `json:"pairConfirm"`
	}{
		DeviceID:         id.DeviceID,
		Ed25519PublicKey: id.Ed25519PublicKeyBase64(),
		X25519PubKey:     x25519PubKeyBase64,
		Name:             name,
		Nonce:            nonce,
		Signature:        signature,
		PairConfirm:      true,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal pair initiate request: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + "/auth/pair/initiate"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create pair initiate request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	SignRequest(req, hmacSecret)

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(connError(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB max
	if err != nil {
		return nil, fmt.Errorf("read pair initiate response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if hmacErr := CheckHMACRejection(resp.StatusCode, respBody, serverURL); hmacErr != nil {
			return nil, hmacErr
		}
		return nil, errors.New(serverError(resp.StatusCode, respBody))
	}

	var result PairInitiateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse pair initiate response: %w", err)
	}

	// The code is embedded in the '|'-delimited QR payload and the
	// '-'-delimited manual code, so accept only the server's 6-char alphabet.
	if len(result.PairingCode) != 6 || strings.Trim(result.PairingCode, pairingSecretAlphabet) != "" {
		return nil, fmt.Errorf("pair initiate returned invalid pairing code")
	}

	return &result, nil
}

// pairDecisionMessage is the host's pair_accept or pair_reject answer to
// pair_complete.
type pairDecisionMessage struct {
	Type           string `json:"type"`
	MobileDeviceID string `json:"mobileDeviceId"`
}

// pairResultMessage is the server's confirmation of a pair_accept: OK is true
// only once the server has committed the pairing.
type pairResultMessage struct {
	Type           string `json:"type"`
	MobileDeviceID string `json:"mobileDeviceId"`
	OK             bool   `json:"ok"`
	Error          string `json:"error,omitempty"`
}

const (
	// pairWriteTimeout bounds each write on the pairing WebSocket.
	pairWriteTimeout = 5 * time.Second
	// pairAuthTimeout bounds the wait for the server's auth reply.
	pairAuthTimeout = 10 * time.Second
	// pairKeepaliveInterval is how often the session sends presence while it
	// waits for pair_complete. The server closes sockets idle for 90s.
	pairKeepaliveInterval = 30 * time.Second
)

// PairAcceptTimeout is how long Accept waits for the server's pair_result.
const PairAcceptTimeout = 10 * time.Second

// PairTimeout is the default timeout for waiting for mobile to complete pairing.
const PairTimeout = 5 * time.Minute

// PairSession is an authenticated pairing WebSocket on which the host waits
// for the mobile's pair_complete. In confirmed mode the server holds the
// mobile's pairing request for at most 30s from when the mobile sent it, so
// the host must answer pair_complete promptly with Accept or Reject. Callers
// must Close it.
type PairSession struct {
	conn *websocket.Conn
	// confirm is true when the server holds pair_complete for the host's
	// decision. Without it the session never sends pair_accept or
	// pair_reject.
	confirm bool
	// keepaliveInterval is how often WaitForPairComplete sends presence.
	keepaliveInterval time.Duration
	// early is a pair_complete that arrived before the auth reply.
	early *PairCompleteMessage
	// received is the pair_complete taken off the wire, valid or not. It is
	// the one Accept, Reject and Close answer.
	received *PairCompleteMessage
	// decided is set once pair_accept or pair_reject has been attempted.
	decided bool
}

// DialPairSession connects to the server WebSocket and authenticates. confirm
// must be the server's PairInitiateResponse.PairConfirm. Every error closes
// the connection.
func DialPairSession(ctx context.Context, serverURL string, jwt string, hmacSecret string, confirm bool) (*PairSession, error) {
	// Convert HTTP URL to WebSocket URL
	wsURL := strings.TrimRight(serverURL, "/") + "/ws"
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

	dialer := websocket.DefaultDialer
	conn, resp, err := dialer.DialContext(ctx, wsURL, SignWebSocketHeaders(wsURL, hmacSecret))
	if err != nil {
		if resp != nil && resp.Body != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if hmacErr := CheckHMACRejection(resp.StatusCode, body, serverURL); hmacErr != nil {
				return nil, hmacErr
			}
		}
		return nil, fmt.Errorf("connect to signaling server: %s", connError(err))
	}
	// gorilla's default read limit is unlimited; a hostile server could
	// otherwise stream one huge frame into memory.
	conn.SetReadLimit(maxPairMessageSize)

	s := &PairSession{conn: conn, confirm: confirm, keepaliveInterval: pairKeepaliveInterval}
	if err := s.authenticate(ctx, jwt); err != nil {
		conn.Close()
		return nil, err
	}
	return s, nil
}

// authenticate sends the JWT and reads until the server's auth reply. A
// pair_complete the server delivers first is kept for WaitForPairComplete.
func (s *PairSession) authenticate(ctx context.Context, jwt string) error {
	authMsg := fmt.Sprintf(`{"type":"auth","token":%q}`, jwt)
	s.conn.SetWriteDeadline(time.Now().Add(pairWriteTimeout))
	err := s.conn.WriteMessage(websocket.TextMessage, []byte(authMsg))
	s.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("send auth message: %w", err)
	}

	deadline := time.Now().Add(pairAuthTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	s.conn.SetReadDeadline(deadline)
	defer s.conn.SetReadDeadline(time.Time{})
	for {
		_, data, err := s.conn.ReadMessage()
		if err != nil {
			// Close errors carry the server's close-reason text; sanitize it.
			return fmt.Errorf("read auth response: %s", SanitizeDisplayString(err.Error()))
		}

		var msg struct {
			Type  string `json:"type"`
			Error string `json:"error,omitempty"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue // skip malformed messages
		}
		switch msg.Type {
		case "auth":
			return nil
		case "error":
			return fmt.Errorf("WebSocket auth failed: %s", SanitizeDisplayString(msg.Error))
		case "pair_complete":
			if s.early == nil {
				var pc PairCompleteMessage
				if err := json.Unmarshal(data, &pc); err == nil {
					s.early = &pc
				}
			}
		}
	}
}

// WaitForPairComplete waits until the mobile's pair_complete arrives or ctx
// ends, sending presence every keepaliveInterval and ignoring other frames.
// A pair_complete with an invalid mobileDeviceId is an error, but Close still
// rejects it in confirmed mode.
func (s *PairSession) WaitForPairComplete(ctx context.Context) (*PairCompleteMessage, error) {
	if s.received != nil {
		return nil, errors.New("pair_complete was already received")
	}
	if s.early != nil {
		s.received, s.early = s.early, nil
	} else if err := s.readPairComplete(ctx); err != nil {
		return nil, err
	}
	if err := ValidateDeviceID(s.received.MobileDeviceID); err != nil {
		return nil, fmt.Errorf("pair_complete: %w", err)
	}
	return s.received, nil
}

// readPairComplete reads until pair_complete, which it stores in s.received,
// while sending presence keepalives. Its reader and keepalive goroutines have
// both exited when it returns, so the caller is again the connection's only
// reader and writer.
func (s *PairSession) readPairComplete(ctx context.Context) error {
	stop := make(chan struct{})
	keepaliveDone := make(chan struct{})
	go func() {
		defer close(keepaliveDone)
		s.keepalive(stop)
	}()
	defer func() {
		close(stop)
		<-keepaliveDone
	}()

	type readResult struct {
		msg *PairCompleteMessage
		err error
	}
	results := make(chan readResult, 1)
	go func() {
		for {
			_, data, err := s.conn.ReadMessage()
			if err != nil {
				// Close errors carry the server's close-reason text; sanitize it.
				results <- readResult{err: fmt.Errorf("read WebSocket message: %s", SanitizeDisplayString(err.Error()))}
				return
			}
			var msg PairCompleteMessage
			if err := json.Unmarshal(data, &msg); err != nil || msg.Type != "pair_complete" {
				continue // skip malformed messages, presence_ack and the like
			}
			results <- readResult{msg: &msg}
			return
		}
	}()

	select {
	case r := <-results:
		s.received = r.msg
		return r.err
	case <-ctx.Done():
		// Unblock the reader and wait for it so it can't outlive this call.
		s.conn.SetReadDeadline(time.Now())
		// A pair_complete that raced the deadline is still recorded, so
		// Close rejects it instead of leaving the mobile waiting.
		s.received = (<-results).msg
		return fmt.Errorf("pairing timed out: %w", ctx.Err())
	}
}

// keepalive sends presence every keepaliveInterval until stop is closed, so
// the server doesn't close the socket as idle. It is the connection's only
// writer while it runs.
func (s *PairSession) keepalive(stop <-chan struct{}) {
	ticker := time.NewTicker(s.keepaliveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			s.conn.SetWriteDeadline(time.Now().Add(pairWriteTimeout))
			err := s.conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"presence"}`))
			s.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				return // the reader reports the broken connection
			}
		}
	}
}

// Reject tells the server not to commit the received pairing.
func (s *PairSession) Reject() error {
	if err := s.checkDecidable(); err != nil {
		return err
	}
	return s.sendDecision("pair_reject", s.received.MobileDeviceID)
}

// Accept tells the server to commit the received pairing and waits up to
// timeout for its pair_result. It returns nil only if the server confirmed
// the commit.
func (s *PairSession) Accept(timeout time.Duration) error {
	if err := s.checkDecidable(); err != nil {
		return err
	}
	if err := s.sendDecision("pair_accept", s.received.MobileDeviceID); err != nil {
		return err
	}

	s.conn.SetReadDeadline(time.Now().Add(timeout))
	defer s.conn.SetReadDeadline(time.Time{})
	for {
		_, data, err := s.conn.ReadMessage()
		if err != nil {
			// The server may have committed before the connection failed.
			// Close errors carry the server's close-reason text; sanitize it.
			return fmt.Errorf("no pair_result from the server (%s); the pairing state is unknown, run 'pmux pair' again", SanitizeDisplayString(err.Error()))
		}

		var msg pairResultMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue // skip malformed messages
		}
		switch msg.Type {
		case "pair_result":
			if msg.MobileDeviceID != s.received.MobileDeviceID {
				continue
			}
			if !msg.OK {
				return errors.New("server did not confirm the pairing (the mobile may have timed out)")
			}
			return nil
		case "error":
			return fmt.Errorf("server refused pair_accept: %s", SanitizeDisplayString(msg.Error))
		}
	}
}

// checkDecidable reports whether Accept or Reject may answer the session.
func (s *PairSession) checkDecidable() error {
	if !s.confirm {
		return errors.New("server does not hold pairings for confirmation")
	}
	if s.received == nil {
		return errors.New("no pair_complete to answer")
	}
	return nil
}

// Close closes the pairing WebSocket. In confirmed mode it first rejects a
// pair_complete that was received but not answered, so the server fails the
// mobile's request at once instead of when its hold expires, and returns the
// error from sending that rejection.
func (s *PairSession) Close() error {
	var err error
	msg := s.received
	if msg == nil {
		msg = s.early
	}
	if s.confirm && msg != nil && !s.decided {
		err = s.sendDecision("pair_reject", msg.MobileDeviceID)
	}
	s.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(pairWriteTimeout))
	s.conn.Close()
	return err
}

func (s *PairSession) sendDecision(decision string, mobileDeviceID string) error {
	// A failed send isn't retried; the server's hold expires instead.
	s.decided = true
	data, err := json.Marshal(pairDecisionMessage{Type: decision, MobileDeviceID: mobileDeviceID})
	if err != nil {
		return fmt.Errorf("marshal %s: %w", decision, err)
	}
	s.conn.SetWriteDeadline(time.Now().Add(pairWriteTimeout))
	defer s.conn.SetWriteDeadline(time.Time{})
	if err := s.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		return fmt.Errorf("send %s: %w", decision, err)
	}
	return nil
}
