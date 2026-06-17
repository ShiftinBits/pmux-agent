package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// tokenResponse represents the server's response to a token exchange request (internal-only).
type tokenResponse struct {
	Token string `json:"token"`
	Error string `json:"error,omitempty"`
}

// fetchChallenge requests a single-use nonce from the server for challenge signing.
// The nonce is used in place of a timestamp to prevent JWT replay attacks.
func fetchChallenge(deviceID, serverURL string, client *http.Client, hmacSecret string) (string, error) {
	reqBody := struct {
		DeviceID string `json:"deviceId"`
	}{DeviceID: deviceID}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal challenge request: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + "/auth/challenge"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create challenge request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	SignRequest(req, hmacSecret)

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New(connError(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB max
	if err != nil {
		return "", fmt.Errorf("read challenge response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if hmacErr := CheckHMACRejection(resp.StatusCode, respBody, serverURL); hmacErr != nil {
			return "", hmacErr
		}
		return "", errors.New(serverError(resp.StatusCode, respBody))
	}

	var chalResp struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(respBody, &chalResp); err != nil {
		return "", fmt.Errorf("parse challenge response: %w", err)
	}

	if chalResp.Nonce == "" {
		return "", fmt.Errorf("challenge response returned empty nonce")
	}

	return chalResp.Nonce, nil
}

// ExchangeToken fetches a server-issued nonce, signs the challenge with the identity
// key, and exchanges it for a JWT.
// serverURL should be the base URL of the signaling server (e.g., "https://signal.pmux.io").
func ExchangeToken(id *Identity, serverURL string, client *http.Client, hmacSecret string) (string, error) {
	nonce, err := fetchChallenge(id.DeviceID, serverURL, client, hmacSecret)
	if err != nil {
		return "", err
	}
	signature := id.SignChallenge(id.DeviceID, nonce)

	reqBody := struct {
		DeviceID  string `json:"deviceId"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	}{
		DeviceID:  id.DeviceID,
		Nonce:     nonce,
		Signature: signature,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal token request: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + "/auth/token"
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	SignRequest(req, hmacSecret)

	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New(connError(err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024)) // 64KB max
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if hmacErr := CheckHMACRejection(resp.StatusCode, respBody, serverURL); hmacErr != nil {
			return "", hmacErr
		}
		return "", errors.New(serverError(resp.StatusCode, respBody))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}

	if tokenResp.Token == "" {
		return "", fmt.Errorf("token exchange returned empty token")
	}

	return tokenResp.Token, nil
}
