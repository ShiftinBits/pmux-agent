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
		// PairConfirm asks the server to hold the pairing until this host
		// answers pair_complete with pair_accept or pair_reject.
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

// pairWriteTimeout bounds each write on the pairing WebSocket.
const pairWriteTimeout = 5 * time.Second

// PairAcceptTimeout is how long Accept waits for the server's pair_result.
const PairAcceptTimeout = 10 * time.Second

// PairSession is an open pairing WebSocket on which pair_complete has been
// received. The server holds the pairing until the host answers with Accept
// or Reject. Callers must Close it.
type PairSession struct {
	Message *PairCompleteMessage
	conn    *websocket.Conn
}

// Reject tells the server not to commit the pairing.
func (s *PairSession) Reject() error {
	return s.sendDecision("pair_reject")
}

// Accept tells the server to commit the pairing and waits up to timeout for
// its pair_result. It returns nil only if the server confirmed the commit.
func (s *PairSession) Accept(timeout time.Duration) error {
	if err := s.sendDecision("pair_accept"); err != nil {
		return err
	}

	s.conn.SetReadDeadline(time.Now().Add(timeout))
	defer s.conn.SetReadDeadline(time.Time{})
	for {
		_, data, err := s.conn.ReadMessage()
		if err != nil {
			// Close errors carry the server's close-reason text; sanitize it.
			return fmt.Errorf("wait for pair_result: %s", SanitizeDisplayString(err.Error()))
		}

		var msg pairResultMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue // skip malformed messages
		}
		switch msg.Type {
		case "pair_result":
			if msg.MobileDeviceID != s.Message.MobileDeviceID {
				continue
			}
			if !msg.OK {
				return errors.New("server did not confirm the pairing (the mobile may have timed out)")
			}
			return nil
		case "error":
			// A server without confirmed pairing answers pair_accept as an
			// unknown message type.
			return fmt.Errorf("server does not support confirmed pairing; it may need updating: %s", SanitizeDisplayString(msg.Error))
		}
	}
}

// Close closes the pairing WebSocket.
func (s *PairSession) Close() error {
	s.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(pairWriteTimeout))
	return s.conn.Close()
}

func (s *PairSession) sendDecision(decision string) error {
	data, err := json.Marshal(pairDecisionMessage{Type: decision, MobileDeviceID: s.Message.MobileDeviceID})
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

// WaitForPairComplete connects to the server WebSocket, authenticates, and waits
// for the pair_complete message. On success the connection stays open in the
// returned PairSession so the host can answer it; every error closes it.
// The context can be used for timeout/cancellation.
func WaitForPairComplete(ctx context.Context, serverURL string, jwt string, hmacSecret string) (*PairSession, error) {
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
	keepOpen := false
	defer func() {
		if !keepOpen {
			conn.Close()
		}
	}()
	// gorilla's default read limit is unlimited; a hostile server could
	// otherwise stream one huge frame into memory.
	conn.SetReadLimit(maxPairMessageSize)

	// Authenticate with JWT
	authMsg := fmt.Sprintf(`{"type":"auth","token":%q}`, jwt)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(authMsg)); err != nil {
		return nil, fmt.Errorf("send auth message: %w", err)
	}

	// Read auth response
	_, authResp, err := conn.ReadMessage()
	if err != nil {
		// Close errors carry the server's close-reason text; sanitize it.
		return nil, fmt.Errorf("read auth response: %s", SanitizeDisplayString(err.Error()))
	}

	var authResult struct {
		Type  string `json:"type"`
		Error string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(authResp, &authResult); err != nil {
		return nil, fmt.Errorf("parse auth response: %w", err)
	}
	if authResult.Type == "error" {
		return nil, fmt.Errorf("WebSocket auth failed: %s", SanitizeDisplayString(authResult.Error))
	}

	// Wait for pair_complete message with context deadline
	resultCh := make(chan *PairCompleteMessage, 1)
	errCh := make(chan error, 1)

	go func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				errCh <- fmt.Errorf("read WebSocket message: %s", SanitizeDisplayString(err.Error()))
				return
			}

			var msg PairCompleteMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				continue // skip malformed messages
			}

			if msg.Type == "pair_complete" {
				if err := ValidateDeviceID(msg.MobileDeviceID); err != nil {
					errCh <- fmt.Errorf("pair_complete: %w", err)
					return
				}
				resultCh <- &msg
				return
			}
			// Ignore other message types (presence acks, etc.)
		}
	}()

	select {
	case msg := <-resultCh:
		// The reader goroutine has returned, so the session is the
		// connection's only reader from here on.
		keepOpen = true
		return &PairSession{Message: msg, conn: conn}, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		return nil, fmt.Errorf("pairing timed out: %w", ctx.Err())
	}
}

// PairTimeout is the default timeout for waiting for mobile to complete pairing.
const PairTimeout = 5 * time.Minute
