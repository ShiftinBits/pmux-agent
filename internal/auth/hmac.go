package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// SignRequest attaches pmux-signature and pmux-timestamp headers to an HTTP request.
// No-op if secret is empty. Uses crypto/hmac, crypto/sha256, encoding/hex.
func SignRequest(req *http.Request, secret string) {
	if secret == "" {
		return
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	path := req.URL.Path
	signature := computeHMAC(secret, timestamp, path)

	req.Header.Set("pmux-timestamp", timestamp)
	req.Header.Set("pmux-signature", signature)
}

// SignWebSocketHeaders returns HTTP headers with HMAC signature for a WebSocket URL.
// Returns nil if secret is empty. Extracts path from the URL.
func SignWebSocketHeaders(wsURL string, secret string) http.Header {
	if secret == "" {
		return nil
	}

	parsed, err := url.Parse(wsURL)
	if err != nil {
		return nil
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	path := parsed.Path
	signature := computeHMAC(secret, timestamp, path)

	headers := http.Header{}
	headers.Set("pmux-timestamp", timestamp)
	headers.Set("pmux-signature", signature)
	return headers
}

// computeHMAC computes HMAC-SHA256(secret, "{timestamp}:{path}") and returns hex-encoded result.
func computeHMAC(secret, timestamp, path string) string {
	message := timestamp + ":" + path
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
