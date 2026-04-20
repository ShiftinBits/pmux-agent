package auth

import (
	"net/http"
	"strings"
	"testing"
)

func TestSignRequest(t *testing.T) {
	tests := []struct {
		name          string
		secret        string
		url           string
		wantTimestamp bool
		wantSignature bool
		wantNonce     bool
	}{
		{
			name:          "v1 path signs with nonce",
			secret:        "my-secret",
			url:           "https://signal.pmux.io/v1/auth/token",
			wantTimestamp: true,
			wantSignature: true,
			wantNonce:     true,
		},
		{
			name:          "legacy path signs without nonce",
			secret:        "my-secret",
			url:           "https://signal.pmux.io/auth/token",
			wantTimestamp: true,
			wantSignature: true,
			wantNonce:     false,
		},
		{
			name:          "empty secret leaves headers unchanged",
			secret:        "",
			url:           "https://signal.pmux.io/v1/auth/token",
			wantTimestamp: false,
			wantSignature: false,
			wantNonce:     false,
		},
		{
			name:          "empty secret on legacy path leaves headers unchanged",
			secret:        "",
			url:           "https://signal.pmux.io/auth/token",
			wantTimestamp: false,
			wantSignature: false,
			wantNonce:     false,
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
			hasSignature := req.Header.Get("pmux-signature") != ""
			hasNonce := req.Header.Get("pmux-nonce") != ""

			if hasTimestamp != tt.wantTimestamp {
				t.Errorf("pmux-timestamp: got %v, want %v", hasTimestamp, tt.wantTimestamp)
			}
			if hasSignature != tt.wantSignature {
				t.Errorf("pmux-signature: got %v, want %v", hasSignature, tt.wantSignature)
			}
			if hasNonce != tt.wantNonce {
				t.Errorf("pmux-nonce: got %v, want %v", hasNonce, tt.wantNonce)
			}
		})
	}
}

func TestSignRequest_NonceIsUnique(t *testing.T) {
	// Two consecutive v1 signatures must produce distinct nonces; if they
	// don't, every replay-protection guarantee of the v1 formula is lost.
	req1, _ := http.NewRequest("POST", "https://signal.pmux.io/v1/auth/token", nil)
	req2, _ := http.NewRequest("POST", "https://signal.pmux.io/v1/auth/token", nil)

	SignRequest(req1, "my-secret")
	SignRequest(req2, "my-secret")

	n1 := req1.Header.Get("pmux-nonce")
	n2 := req2.Header.Get("pmux-nonce")
	if n1 == "" || n2 == "" {
		t.Fatalf("expected non-empty nonces, got %q and %q", n1, n2)
	}
	if n1 == n2 {
		t.Errorf("expected unique nonces, got identical value %q", n1)
	}
}

func TestSignWebSocketHeaders(t *testing.T) {
	tests := []struct {
		name          string
		wsURL         string
		secret        string
		wantNil       bool
		wantTimestamp bool
		wantSignature bool
		wantNonce     bool
	}{
		{
			name:          "v1 path returns headers with nonce",
			wsURL:         "wss://signal.pmux.io/v1/ws",
			secret:        "my-secret",
			wantNil:       false,
			wantTimestamp: true,
			wantSignature: true,
			wantNonce:     true,
		},
		{
			name:          "legacy path returns headers without nonce",
			wsURL:         "wss://signal.pmux.io/ws",
			secret:        "my-secret",
			wantNil:       false,
			wantTimestamp: true,
			wantSignature: true,
			wantNonce:     false,
		},
		{
			name:    "empty secret returns nil",
			wsURL:   "wss://signal.pmux.io/v1/ws",
			secret:  "",
			wantNil: true,
		},
		{
			name:    "empty secret on legacy path returns nil",
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
			if tt.wantTimestamp && headers.Get("pmux-timestamp") == "" {
				t.Error("missing pmux-timestamp header")
			}
			if tt.wantSignature && headers.Get("pmux-signature") == "" {
				t.Error("missing pmux-signature header")
			}
			hasNonce := headers.Get("pmux-nonce") != ""
			if hasNonce != tt.wantNonce {
				t.Errorf("pmux-nonce: got %v, want %v", hasNonce, tt.wantNonce)
			}
		})
	}
}

func TestCrossplatformTestVector(t *testing.T) {
	// Cross-platform test vector — MUST match server and mobile implementations.
	secret := "test-hmac-secret-for-pocketmux"
	timestamp := "1709654400"
	path := "/auth/token"
	expectedHex := "724c81d78ba888524abb90d0de772502eda085ceb125c0fb8b2aaddeb3d0604c"

	got := computeHMAC(secret, timestamp, path)
	if got != expectedHex {
		t.Errorf("cross-platform test vector mismatch\n  got:  %s\n  want: %s", got, expectedHex)
	}
}

func TestComputeHMAC_KnownInputs(t *testing.T) {
	tests := []struct {
		name      string
		secret    string
		timestamp string
		path      string
		wantHex   string
	}{
		{
			name:      "cross-platform vector",
			secret:    "test-hmac-secret-for-pocketmux",
			timestamp: "1709654400",
			path:      "/auth/token",
			wantHex:   "724c81d78ba888524abb90d0de772502eda085ceb125c0fb8b2aaddeb3d0604c",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeHMAC(tt.secret, tt.timestamp, tt.path)
			if got != tt.wantHex {
				t.Errorf("computeHMAC() = %s, want %s", got, tt.wantHex)
			}
		})
	}
}

func TestComputeHMACv1_DifferentFromLegacy(t *testing.T) {
	// v1 and legacy formulas must produce different digests for the same
	// (secret, timestamp, path) — otherwise a server could be tricked into
	// accepting a v1 signature for a legacy endpoint.
	secret := "test-hmac-secret-for-pocketmux"
	timestamp := "1709654400"
	path := "/v1/auth/token"
	nonce := "abc123"

	legacy := computeHMAC(secret, timestamp, path)
	v1 := computeHMACv1(secret, timestamp, nonce, path)

	if legacy == v1 {
		t.Errorf("legacy and v1 HMACs unexpectedly matched: %s", legacy)
	}
}

func TestComputeHMACv1_NonceChangesDigest(t *testing.T) {
	secret := "test-hmac-secret-for-pocketmux"
	timestamp := "1709654400"
	path := "/v1/auth/token"

	a := computeHMACv1(secret, timestamp, "nonce-a", path)
	b := computeHMACv1(secret, timestamp, "nonce-b", path)
	if a == b {
		t.Errorf("different nonces should produce different digests, got %s", a)
	}
}

func TestGenerateNonce(t *testing.T) {
	n1 := generateNonce()
	n2 := generateNonce()

	if n1 == "" {
		t.Fatal("generateNonce() returned empty string")
	}
	// Hex encoding doubles the byte length.
	if want := hmacNonceSize * 2; len(n1) != want {
		t.Errorf("nonce length = %d, want %d", len(n1), want)
	}
	if n1 == n2 {
		t.Errorf("expected unique nonces, got identical value %q", n1)
	}
	// Should be pure hex.
	if strings.TrimLeft(n1, "0123456789abcdef") != "" {
		t.Errorf("nonce %q contains non-hex characters", n1)
	}
}
