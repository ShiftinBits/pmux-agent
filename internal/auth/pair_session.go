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
// Tries JSON {"error":"..."} first, falls back to truncated raw body.
func serverError(statusCode int, body []byte) string {
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Error != "" {
		return fmt.Sprintf("server error (%d): %s", statusCode, parsed.Error)
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	return fmt.Sprintf("server error (%d): %s", statusCode, msg)
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
}

// InitiatePairing calls the server to create a pairing session.
// The name parameter is an optional human-readable host name sent to the server
// so it can be displayed on paired mobile devices.
func InitiatePairing(id *Identity, x25519PubKeyBase64 string, serverURL string, client *http.Client, name string, hmacSecret string) (*PairInitiateResponse, error) {
	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	signature := id.SignChallenge(id.DeviceID, timestamp)

	reqBody := struct {
		DeviceID         string `json:"deviceId"`
		Ed25519PublicKey string `json:"ed25519PublicKey"`
		X25519PubKey     string `json:"x25519PublicKey"`
		Name             string `json:"name,omitempty"`
		Timestamp        string `json:"timestamp"`
		Signature        string `json:"signature"`
	}{
		DeviceID:         id.DeviceID,
		Ed25519PublicKey: id.Ed25519PublicKeyBase64(),
		X25519PubKey:     x25519PubKeyBase64,
		Name:             name,
		Timestamp:        timestamp,
		Signature:        signature,
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

	if result.PairingCode == "" {
		return nil, fmt.Errorf("pair initiate returned empty pairing code")
	}

	return &result, nil
}

// WaitForPairComplete connects to the server WebSocket, authenticates, and waits
// for the pair_complete message. Returns the mobile's X25519 public key and device ID.
// The context can be used for timeout/cancellation.
func WaitForPairComplete(ctx context.Context, serverURL string, jwt string, hmacSecret string) (*PairCompleteMessage, error) {
	// Convert HTTP URL to WebSocket URL
	wsURL := strings.TrimRight(serverURL, "/") + "/ws"
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

	dialer := websocket.DefaultDialer
	conn, resp, err := dialer.DialContext(ctx, wsURL, SignWebSocketHeaders(wsURL, hmacSecret))
	if err != nil {
		if resp != nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if hmacErr := CheckHMACRejection(resp.StatusCode, body, serverURL); hmacErr != nil {
				return nil, hmacErr
			}
		}
		return nil, fmt.Errorf("connect to signaling server: %s", connError(err))
	}
	defer conn.Close()

	// Authenticate with JWT
	authMsg := fmt.Sprintf(`{"type":"auth","token":%q}`, jwt)
	if err := conn.WriteMessage(websocket.TextMessage, []byte(authMsg)); err != nil {
		return nil, fmt.Errorf("send auth message: %w", err)
	}

	// Read auth response
	_, authResp, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read auth response: %w", err)
	}

	var authResult struct {
		Type  string `json:"type"`
		Error string `json:"error,omitempty"`
	}
	if err := json.Unmarshal(authResp, &authResult); err != nil {
		return nil, fmt.Errorf("parse auth response: %w", err)
	}
	if authResult.Type == "error" {
		return nil, fmt.Errorf("WebSocket auth failed: %s", authResult.Error)
	}

	// Wait for pair_complete message with context deadline
	resultCh := make(chan *PairCompleteMessage, 1)
	errCh := make(chan error, 1)

	go func() {
		for {
			_, data, err := conn.ReadMessage()
			if err != nil {
				errCh <- fmt.Errorf("read WebSocket message: %w", err)
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
		return msg, nil
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
