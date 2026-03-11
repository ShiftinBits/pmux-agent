package auth

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestIsHMACRejection(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		errorMsg   string
		want       bool
	}{
		{
			name:       "missing client signature",
			statusCode: 401,
			errorMsg:   "missing client signature",
			want:       true,
		},
		{
			name:       "invalid client signature",
			statusCode: 401,
			errorMsg:   "invalid client signature",
			want:       true,
		},
		{
			name:       "invalid timestamp",
			statusCode: 401,
			errorMsg:   "invalid timestamp",
			want:       true,
		},
		{
			name:       "request expired is transient, not permanent",
			statusCode: 401,
			errorMsg:   "request expired",
			want:       false,
		},
		{
			name:       "non-HMAC 401 error",
			statusCode: 401,
			errorMsg:   "Authentication failed",
			want:       false,
		},
		{
			name:       "403 with HMAC message is not a match",
			statusCode: 403,
			errorMsg:   "missing client signature",
			want:       false,
		},
		{
			name:       "200 is never a rejection",
			statusCode: 200,
			errorMsg:   "missing client signature",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsHMACRejection(tt.statusCode, tt.errorMsg)
			if got != tt.want {
				t.Errorf("IsHMACRejection(%d, %q) = %v, want %v", tt.statusCode, tt.errorMsg, got, tt.want)
			}
		})
	}
}

func TestCheckHMACRejection(t *testing.T) {
	makeBody := func(errorMsg string) []byte {
		b, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{Error: errorMsg})
		return b
	}

	tests := []struct {
		name       string
		statusCode int
		body       []byte
		serverURL  string
		wantErr    bool
		wantMsg    string
	}{
		{
			name:       "401 with missing client signature",
			statusCode: 401,
			body:       makeBody("missing client signature"),
			serverURL:  "https://signal.pmux.io",
			wantErr:    true,
			wantMsg:    "missing client signature",
		},
		{
			name:       "401 with invalid client signature",
			statusCode: 401,
			body:       makeBody("invalid client signature"),
			serverURL:  "https://signal.pmux.io",
			wantErr:    true,
			wantMsg:    "invalid client signature",
		},
		{
			name:       "401 with request expired returns nil (transient)",
			statusCode: 401,
			body:       makeBody("request expired"),
			serverURL:  "https://signal.pmux.io",
			wantErr:    false,
		},
		{
			name:       "401 with non-HMAC error returns nil",
			statusCode: 401,
			body:       makeBody("Authentication failed"),
			serverURL:  "https://signal.pmux.io",
			wantErr:    false,
		},
		{
			name:       "500 returns nil",
			statusCode: 500,
			body:       makeBody("internal server error"),
			serverURL:  "https://signal.pmux.io",
			wantErr:    false,
		},
		{
			name:       "401 with invalid JSON returns nil",
			statusCode: 401,
			body:       []byte("not json"),
			serverURL:  "https://signal.pmux.io",
			wantErr:    false,
		},
		{
			name:       "401 with empty body returns nil",
			statusCode: 401,
			body:       []byte(""),
			serverURL:  "https://signal.pmux.io",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckHMACRejection(tt.statusCode, tt.body, tt.serverURL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				var hmacErr *HMACRejectedError
				if !errors.As(err, &hmacErr) {
					t.Fatalf("expected *HMACRejectedError, got %T", err)
				}
				if hmacErr.ServerURL != tt.serverURL {
					t.Errorf("ServerURL = %q, want %q", hmacErr.ServerURL, tt.serverURL)
				}
				if hmacErr.ServerMsg != tt.wantMsg {
					t.Errorf("ServerMsg = %q, want %q", hmacErr.ServerMsg, tt.wantMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("expected nil, got %v", err)
				}
			}
		})
	}
}

func TestHMACRejectedError_Error(t *testing.T) {
	err := &HMACRejectedError{
		ServerURL: "https://signal.pmux.io",
		ServerMsg: "missing client signature",
	}
	got := err.Error()
	want := "agent not recognized by signaling server at https://signal.pmux.io: missing client signature (rebuild with correct credentials or update pmux)"
	if got != want {
		t.Errorf("Error() =\n  %q\nwant:\n  %q", got, want)
	}
}
