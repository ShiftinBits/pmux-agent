package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

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
}

// InitiatePairing calls the server to create a pairing session.
func InitiatePairing(id *Identity, x25519PubKeyBase64 string, serverURL string, client *http.Client) (*PairInitiateResponse, error) {
	reqBody := struct {
		DeviceID       string `json:"deviceId"`
		PublicKey      string `json:"publicKey"`
		X25519PubKey   string `json:"x25519PublicKey"`
	}{
		DeviceID:     id.DeviceID,
		PublicKey:    id.PublicKeyBase64(),
		X25519PubKey: x25519PubKeyBase64,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal pair initiate request: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + "/auth/pair/initiate"
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("pair initiate request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read pair initiate response: %w", err)
	}

	var result PairInitiateResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse pair initiate response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pair initiate failed (%d): %s", resp.StatusCode, result.Error)
	}

	if result.PairingCode == "" {
		return nil, fmt.Errorf("pair initiate returned empty pairing code")
	}

	return &result, nil
}

// WaitForPairComplete connects to the server WebSocket, authenticates, and waits
// for the pair_complete message. Returns the mobile's X25519 public key and device ID.
// The context can be used for timeout/cancellation.
func WaitForPairComplete(ctx context.Context, serverURL string, jwt string) (*PairCompleteMessage, error) {
	// Convert HTTP URL to WebSocket URL
	wsURL := strings.TrimRight(serverURL, "/") + "/ws"
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

	dialer := websocket.DefaultDialer
	conn, _, err := dialer.DialContext(ctx, wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to signaling server: %w", err)
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
