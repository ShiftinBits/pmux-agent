package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// deleteFromServer performs an authenticated DELETE request to the given
// server endpoint path. It exchanges a JWT token first, then sends the
// DELETE with a Bearer authorization header.
func deleteFromServer(identity *Identity, serverURL string, path string, client *http.Client) error {
	token, err := ExchangeToken(identity, serverURL, client)
	if err != nil {
		return fmt.Errorf("token exchange: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + path
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("create delete request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return errors.New(connError(err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return errors.New(serverError(resp.StatusCode, body))
	}

	return nil
}

// DeletePairing calls DELETE /auth/pairing on the signaling server to remove
// the pairing record and notify the mobile device.
func DeletePairing(identity *Identity, serverURL string, client *http.Client) error {
	return deleteFromServer(identity, serverURL, "/auth/pairing", client)
}

// DeleteDevice calls DELETE /auth/device on the signaling server to remove
// the host device record and its pairing. Used by `pmux uninstall`.
func DeleteDevice(identity *Identity, serverURL string, client *http.Client) error {
	return deleteFromServer(identity, serverURL, "/auth/device", client)
}
