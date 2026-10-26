package auth

import (
	"bytes"
	"context"
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
	return fetchChallengeContext(context.Background(), deviceID, serverURL, client, hmacSecret)
}

// fetchChallengeContext is fetchChallenge bound to ctx.
func fetchChallengeContext(ctx context.Context, deviceID, serverURL string, client *http.Client, hmacSecret string) (string, error) {
	reqBody := struct {
		DeviceID string `json:"deviceId"`
	}{DeviceID: deviceID}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal challenge request: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + "/auth/challenge"
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
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

// withoutRedirects returns a copy of client that hands back 3xx responses
// instead of following them. The challenge signature is bound to the origin of
// the configured server URL, so a redirect (which also turns a POST into a GET)
// would make the server verify against a different origin.
func withoutRedirects(client *http.Client) *http.Client {
	cp := *client
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// signedRequestError builds the error for a non-200 response to a request
// carrying an origin-bound challenge signature. A 401 or 3xx is the
// signature of an origin mismatch (proxy rewrite or redirect) or of a server
// that predates origin-bound verification, so those name the signed origin.
func signedRequestError(statusCode int, body []byte, origin string) error {
	msg := serverError(statusCode, body)
	switch {
	case statusCode == http.StatusUnauthorized:
		msg += fmt.Sprintf(" (challenge was signed for origin %s: the server must be on a version that verifies origin-bound signatures and must see this exact origin)", origin)
	case statusCode >= 300 && statusCode < 400:
		msg += fmt.Sprintf(" (redirects are not followed because the challenge signature is bound to origin %s; point the server URL at the final origin)", origin)
	}
	return errors.New(msg)
}

// ExchangeToken fetches a server-issued nonce, signs the challenge with the identity
// key, and exchanges it for a JWT.
// serverURL should be the base URL of the signaling server (e.g., "https://signal.pmux.io").
//
// The signature is bound to the server's origin (see Identity.SignChallenge) and
// the client never falls back to an unbound form, so the server must be
// deployed with origin-bound verification before agents that use this version.
func ExchangeToken(id *Identity, serverURL string, client *http.Client, hmacSecret string) (string, error) {
	return ExchangeTokenContext(context.Background(), id, serverURL, client, hmacSecret)
}

// ExchangeTokenContext is ExchangeToken bound to ctx: canceling ctx or hitting
// its deadline aborts the in-flight challenge or token request.
func ExchangeTokenContext(ctx context.Context, id *Identity, serverURL string, client *http.Client, hmacSecret string) (string, error) {
	origin, err := canonicalOrigin(serverURL)
	if err != nil {
		return "", fmt.Errorf("canonical server origin: %w", err)
	}
	client = withoutRedirects(client)
	nonce, err := fetchChallengeContext(ctx, id.DeviceID, serverURL, client, hmacSecret)
	if err != nil {
		return "", err
	}
	signature := id.SignChallenge(origin, id.DeviceID, nonce)

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
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
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
		return "", signedRequestError(resp.StatusCode, respBody, origin)
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
