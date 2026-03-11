package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// HMACRejectedError indicates the signaling server rejected the agent's
// client signature. This is a permanent failure — the agent binary was built
// without the correct HMAC secret and retrying will not help.
type HMACRejectedError struct {
	ServerURL string // signaling server base URL
	ServerMsg string // raw error from server (e.g., "missing client signature")
}

func (e *HMACRejectedError) Error() string {
	return fmt.Sprintf(
		"agent not recognized by signaling server at %s: %s (rebuild with correct credentials or update pmux)",
		e.ServerURL, e.ServerMsg,
	)
}

// permanentHMACErrors are server error messages that indicate a permanent
// HMAC configuration mismatch. "request expired" is intentionally excluded
// because clock skew may self-resolve via NTP synchronization.
var permanentHMACErrors = map[string]bool{
	"missing client signature": true,
	"invalid client signature": true,
	"invalid timestamp":        true,
}

// IsHMACRejection returns true if the HTTP status code and server error
// message indicate a permanent HMAC client signature failure.
func IsHMACRejection(statusCode int, errorMsg string) bool {
	return statusCode == http.StatusUnauthorized && permanentHMACErrors[errorMsg]
}

// CheckHMACRejection inspects an HTTP response for HMAC rejection.
// Returns a *HMACRejectedError if the response indicates a permanent HMAC
// failure, or nil if the error is unrelated to HMAC validation.
func CheckHMACRejection(statusCode int, body []byte, serverURL string) error {
	if statusCode != http.StatusUnauthorized {
		return nil
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &parsed) != nil || parsed.Error == "" {
		return nil
	}
	if !permanentHMACErrors[parsed.Error] {
		return nil
	}
	return &HMACRejectedError{
		ServerURL: serverURL,
		ServerMsg: parsed.Error,
	}
}
