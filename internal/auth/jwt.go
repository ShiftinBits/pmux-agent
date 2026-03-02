package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// TokenResponse represents the server's response to a token exchange request.
type TokenResponse struct {
	Token string `json:"token"`
	Error string `json:"error,omitempty"`
}

// ExchangeToken signs a challenge with the identity key and exchanges it for a JWT.
// serverURL should be the base URL of the signaling server (e.g., "https://signal.pmux.io").
func ExchangeToken(id *Identity, serverURL string, client *http.Client) (string, error) {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := id.SignChallenge(id.DeviceID, timestamp)

	reqBody := struct {
		DeviceID  string `json:"deviceId"`
		Timestamp string `json:"timestamp"`
		Signature string `json:"signature"`
	}{
		DeviceID:  id.DeviceID,
		Timestamp: timestamp,
		Signature: signature,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal token request: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + "/auth/token"
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%s", connError(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB max
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", serverError(resp.StatusCode, respBody))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.Token == "" {
		return "", fmt.Errorf("token exchange returned empty token")
	}

	return tokenResp.Token, nil
}
