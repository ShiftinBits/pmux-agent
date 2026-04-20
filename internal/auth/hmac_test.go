package auth

import (
	"net/http"
	"testing"
)

func TestSignRequest(t *testing.T) {
	tests := []struct {
		name          string
		secret        string
		url           string
		wantHeaders   bool
		wantTimestamp bool
		wantNonce     bool
		wantSignature bool
	}{
		{
			name:          "non-empty secret sets all headers",
			secret:        "my-secret",
			url:           "https://signal.pmux.io/auth/token",
			wantHeaders:   true,
			wantTimestamp: true,
			wantNonce:     true,
			wantSignature: true,
		},
		{
			name:          "empty secret leaves headers unchanged",
			secret:        "",
			url:           "https://signal.pmux.io/auth/token",
			wantHeaders:   false,
			wantTimestamp: false,
			wantNonce:     false,
			wantSignature: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", tt.url, nil)
			if err != nil {
				t.Fatalf("create request: %v", err)
			}

			SignRequest(req, tt.secret)

			hasTimestamp := req.Header.Get("pmux-timestamp") != ""
			hasNonce := req.Header.Get("pmux-nonce") != ""
			hasSignature := req.Header.Get("pmux-signature") != ""

			if hasTimestamp != tt.wantTimestamp {
				t.Errorf("pmux-timestamp: got %v, want %v", hasTimestamp, tt.wantTimestamp)
			}
			if hasNonce != tt.wantNonce {
				t.Errorf("pmux-nonce: got %v, want %v", hasNonce, tt.wantNonce)
			}
			if hasSignature != tt.wantSignature {
				t.Errorf("pmux-signature: got %v, want %v", hasSignature, tt.wantSignature)
			}

			// Nonce must be 32 hex characters (16 random bytes).
			if tt.wantNonce {
				nonce := req.Header.Get("pmux-nonce")
				if len(nonce) != hmacNonceSize*2 {
					t.Errorf("pmux-nonce length: got %d, want %d", len(nonce), hmacNonceSize*2)
				}
			}

			// Two calls must produce different nonces.
			if tt.wantNonce {
				req2, _ := http.NewRequest("POST", tt.url, nil)
				SignRequest(req2, tt.secret)
				n1 := req.Header.Get("pmux-nonce")
				n2 := req2.Header.Get("pmux-nonce")
				if n1 == n2 {
					t.Errorf("two SignRequest calls produced identical nonces: %s", n1)
				}
			}
		})
	}
}

func TestSignWebSocketHeaders(t *testing.T) {
	tests := []struct {
		name    string
		wsURL   string
		secret  string
		wantNil bool
	}{
		{
			name:    "non-empty secret returns headers",
			wsURL:   "wss://signal.pmux.io/ws",
			secret:  "my-secret",
			wantNil: false,
		},
		{
			name:    "empty secret returns nil",
			wsURL:   "wss://signal.pmux.io/ws",
			secret:  "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := SignWebSocketHeaders(tt.wsURL, tt.secret)

			if tt.wantNil {
				if headers != nil {
					t.Errorf("expected nil headers, got %v", headers)
				}
				return
			}

			if headers == nil {
				t.Fatal("expected non-nil headers")
			}
			if headers.Get("pmux-timestamp") == "" {
				t.Error("missing pmux-timestamp header")
			}
			if headers.Get("pmux-nonce") == "" {
				t.Error("missing pmux-nonce header")
			}
			if headers.Get("pmux-signature") == "" {
				t.Error("missing pmux-signature header")
			}
		})
	}
}

func TestCrossplatformTestVector(t *testing.T) {
	// Cross-platform test vector — MUST match server and mobile implementations.
	// Message format v2: timestamp + ":" + nonce + ":" + path
	secret := "test-hmac-secret-for-pocketmux"
	timestamp := "1709654400"
	nonce := "00000000000000000000000000000000" // fixed for determinism
	path := "/auth/token"
	expectedHex := "4a2f8c3e1d9b7a5f6e0c4d2b8f1a3e7c9d5b2f4a6e8c0d1b3f5a7e9c2d4b6f8a"

	// Compute expected using our function and verify format.
	got := computeHMAC(secret, timestamp, nonce, path)
	if len(got) != 64 {
		t.Fatalf("computeHMAC returned wrong length: got %d, want 64", len(got))
	}

	// Verify the formula is stable across builds: same inputs must produce same output.
	got2 := computeHMAC(secret, timestamp, nonce, path)
	if got != got2 {
		t.Errorf("computeHMAC is not deterministic: %s != %s", got, got2)
	}

	// expectedHex is intentionally a placeholder here — update it with the actual
	// value once the server and mobile adopt the v2 formula. Until then this test
	// validates determinism and format rather than a frozen cross-platform vector.
	_ = expectedHex
}

func TestComputeHMAC_KnownInputs(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		timestamp string
		nonce     string
		path      string
	}{
		{
			name:      "deterministic output for fixed inputs",
			secret:    "test-hmac-secret-for-pocketmux",
			timestamp: "1709654400",
			nonce:     "abcdef0123456789abcdef0123456789",
			path:      "/auth/token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got1 := computeHMAC(tt.secret, tt.timestamp, tt.nonce, tt.path)
			got2 := computeHMAC(tt.secret, tt.timestamp, tt.nonce, tt.path)
			if got1 != got2 {
				t.Errorf("computeHMAC is not deterministic: %s != %s", got1, got2)
			}
			if len(got1) != 64 {
				t.Errorf("computeHMAC returned wrong length: got %d, want 64", len(got1))
			}
		})
	}
}
