package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const hmacNonceSize = 16 // 16 random bytes → 32 hex chars

// SignRequest attaches pmux-signature, pmux-timestamp, and pmux-nonce headers
// to an HTTP request. No-op if secret is empty.
func SignRequest(req *http.Request, secret string) {
	if secret == "" {
		return
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	nonce := generateNonce()
	path := req.URL.Path
	signature := computeHMAC(secret, timestamp, nonce, path)

	req.Header.Set("pmux-timestamp", timestamp)
	req.Header.Set("pmux-nonce", nonce)
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
	nonce := generateNonce()
	path := parsed.Path
	signature := computeHMAC(secret, timestamp, nonce, path)

	headers := http.Header{}
	headers.Set("pmux-timestamp", timestamp)
	headers.Set("pmux-nonce", nonce)
	headers.Set("pmux-signature", signature)
	return headers
}

// generateNonce returns a hex-encoded 16-byte random nonce.
// Panics if the OS random source fails (unrecoverable in practice).
func generateNonce() string {
	b := make([]byte, hmacNonceSize)
	if _, err := rand.Read(b); err != nil {
		panic("hmac: failed to generate nonce: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// computeHMAC computes HMAC-SHA256(secret, "{timestamp}:{nonce}:{path}") and
// returns the hex-encoded result.
//
// Message format v2: timestamp + ":" + nonce + ":" + path
// The nonce prevents replay attacks within the server's clock-skew window.
// NOTE: this formula must match the server and mobile implementations.
func computeHMAC(secret, timestamp, nonce, path string) string {
	message := timestamp + ":" + nonce + ":" + path
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}
