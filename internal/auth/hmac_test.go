package auth

import (
	"net/http"
	"testing"
)

func TestSignRequest(t *testing.T) {
	tests := []struct {
		name           string
		secret         string
		url            string
		wantHeaders    bool
		wantTimestamp  bool
		wantSignature  bool
	}{
		{
			name:          "non-empty secret sets both headers",
			secret:        "my-secret",
			url:           "https://signal.pmux.io/auth/token",
			wantHeaders:   true,
			wantTimestamp:  true,
			wantSignature: true,
		},
		{
			name:          "empty secret leaves headers unchanged",
			secret:        "",
			url:           "https://signal.pmux.io/auth/token",
			wantHeaders:   false,
			wantTimestamp:  false,
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
			hasSignature := req.Header.Get("pmux-signature") != ""

			if hasTimestamp != tt.wantTimestamp {
				t.Errorf("pmux-timestamp: got %v, want %v", hasTimestamp, tt.wantTimestamp)
			}
			if hasSignature != tt.wantSignature {
				t.Errorf("pmux-signature: got %v, want %v", hasSignature, tt.wantSignature)
			}
		})
	}
}

func TestSignWebSocketHeaders(t *testing.T) {
	tests := []struct {
		name       string
		wsURL      string
		secret     string
		wantNil    bool
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
			if headers.Get("pmux-signature") == "" {
				t.Error("missing pmux-signature header")
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

	got := ComputeHMACForTest(secret, timestamp, path)
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
