package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// hmacNonceSize is the byte length of the random nonce generated for v1
// HMAC-signed requests. 16 bytes (128 bits) of entropy is plenty to make
// replay-window collisions negligible.
const hmacNonceSize = 16

// apiV1Prefix is the URL path prefix that selects the v1 HMAC formula.
// Requests with this prefix are signed with (timestamp:nonce:path) and
// carry a pmux-nonce header; legacy paths keep the (timestamp:path) formula.
const apiV1Prefix = "/v1/"

// SignRequest attaches pmux-signature and pmux-timestamp headers to an HTTP request.
// No-op if secret is empty.
//
// The HMAC formula is auto-selected from the request path:
//   - Paths beginning with "/v1/" use the v1 formula (timestamp:nonce:path) and
//     additionally set a pmux-nonce header carrying a fresh random nonce.
//   - All other paths use the legacy formula (timestamp:path).
//
// This lets callers upgrade to versioned URLs transparently by passing the
// versioned base URL to request-construction helpers; no explicit flag is
// needed.
func SignRequest(req *http.Request, secret string) {
	if secret == "" {
		return
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	path := req.URL.Path

	if strings.HasPrefix(path, apiV1Prefix) {
		nonce := generateNonce()
		signature := computeHMACv1(secret, timestamp, nonce, path)
		req.Header.Set("pmux-timestamp", timestamp)
		req.Header.Set("pmux-nonce", nonce)
		req.Header.Set("pmux-signature", signature)
		return
	}

	signature := computeHMAC(secret, timestamp, path)
	req.Header.Set("pmux-timestamp", timestamp)
	req.Header.Set("pmux-signature", signature)
}

// SignWebSocketHeaders returns HTTP headers with HMAC signature for a WebSocket URL.
// Returns nil if secret is empty. Extracts path from the URL.
//
// Like SignRequest, the formula is auto-selected from the URL path: "/v1/"
// paths use the v1 formula with a pmux-nonce header; all others use the
// legacy formula.
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
	headers := http.Header{}

	if strings.HasPrefix(path, apiV1Prefix) {
		nonce := generateNonce()
		signature := computeHMACv1(secret, timestamp, nonce, path)
		headers.Set("pmux-timestamp", timestamp)
		headers.Set("pmux-nonce", nonce)
		headers.Set("pmux-signature", signature)
		return headers
	}

	signature := computeHMAC(secret, timestamp, path)
	headers.Set("pmux-timestamp", timestamp)
	headers.Set("pmux-signature", signature)
	return headers
}

// computeHMAC computes HMAC-SHA256(secret, "{timestamp}:{path}") and returns
// hex-encoded result. This is the legacy formula, still used for unversioned
// paths so older signaling servers keep working.
func computeHMAC(secret, timestamp, path string) string {
	message := timestamp + ":" + path
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// computeHMACv1 computes HMAC-SHA256(secret, "{timestamp}:{nonce}:{path}")
// and returns hex-encoded result. Added in the /v1/ API to defend against
// replay attacks within the timestamp tolerance window: even identical
// requests now produce different signatures.
func computeHMACv1(secret, timestamp, nonce, path string) string {
	message := timestamp + ":" + nonce + ":" + path
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// generateNonce returns a hex-encoded random nonce suitable for a single
// v1 HMAC-signed request. Uses crypto/rand; panics only if the system
// entropy source is unavailable, which would indicate a broken platform.
func generateNonce() string {
	buf := make([]byte, hmacNonceSize)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand failure on a healthy system is effectively impossible;
		// if it does occur we cannot safely sign the request, so panic loud.
		panic(fmt.Sprintf("auth: generate nonce: %v", err))
	}
	return hex.EncodeToString(buf)
}
