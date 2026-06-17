package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// challengeHandler returns an http.HandlerFunc that handles POST /auth/challenge by
// issuing a fixed test nonce, and POST /auth/token with the provided tokenHandler logic.
func challengeHandler(nonce string, tokenHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/challenge" && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"nonce":"` + nonce + `"}`))
		default:
			tokenHandler(w, r)
		}
	}
}

func TestExchangeToken(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	const testNonce = "test-nonce-abc123"

	t.Run("successful token exchange", func(t *testing.T) {
		server := httptest.NewServer(challengeHandler(testNonce, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/auth/token" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("unexpected method: %s", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
			}

			var body struct {
				DeviceID  string `json:"deviceId"`
				Nonce     string `json:"nonce"`
				Signature string `json:"signature"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if body.DeviceID != id.DeviceID {
				t.Errorf("deviceId = %q, want %q", body.DeviceID, id.DeviceID)
			}
			if body.Nonce != testNonce {
				t.Errorf("nonce = %q, want %q", body.Nonce, testNonce)
			}
			if body.Signature == "" {
				t.Error("signature is empty")
			}

			// Verify signature is over deviceID + "|" + nonce
			sigBytes, err := base64.StdEncoding.DecodeString(body.Signature)
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			message := []byte(body.DeviceID + "|" + body.Nonce)
			if !ed25519.Verify(id.Ed25519PublicKey, message, sigBytes) {
				t.Error("signature verification failed")
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"jwt-token-here"}`))
		}))
		defer server.Close()

		token, err := ExchangeToken(id, server.URL, server.Client(), "")
		if err != nil {
			t.Fatalf("ExchangeToken() error: %v", err)
		}
		if token != "jwt-token-here" {
			t.Errorf("token = %q, want %q", token, "jwt-token-here")
		}
	})

	t.Run("challenge fetch error propagates", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/auth/challenge" {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"internal error"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"ok"}`))
		}))
		defer server.Close()

		_, err := ExchangeToken(id, server.URL, server.Client(), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "server error (500)") {
			t.Errorf("error = %q, want substring %q", err.Error(), "server error (500)")
		}
	})

	t.Run("server returns error on token request", func(t *testing.T) {
		server := httptest.NewServer(challengeHandler(testNonce, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Signature verification failed"}`))
		}))
		defer server.Close()

		_, err := ExchangeToken(id, server.URL, server.Client(), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "server error (401)") {
			t.Errorf("error = %q, want substring %q", err.Error(), "server error (401)")
		}
	})

	t.Run("server returns empty token", func(t *testing.T) {
		server := httptest.NewServer(challengeHandler(testNonce, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":""}`))
		}))
		defer server.Close()

		_, err := ExchangeToken(id, server.URL, server.Client(), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "empty token") {
			t.Errorf("error = %q, want substring %q", err.Error(), "empty token")
		}
	})

	t.Run("network error", func(t *testing.T) {
		_, err := ExchangeToken(id, "http://localhost:1", http.DefaultClient, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("strips trailing slash from server URL", func(t *testing.T) {
		server := httptest.NewServer(challengeHandler(testNonce, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/auth/token" {
				t.Errorf("path = %q, want /auth/token", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"ok"}`))
		}))
		defer server.Close()

		token, err := ExchangeToken(id, server.URL+"/", server.Client(), "")
		if err != nil {
			t.Fatalf("ExchangeToken() error: %v", err)
		}
		if token != "ok" {
			t.Errorf("token = %q, want %q", token, "ok")
		}
	})
}

func TestFetchChallenge(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	t.Run("returns nonce from server", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/auth/challenge" {
				t.Errorf("path = %q, want /auth/challenge", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("method = %q, want POST", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("content type = %q, want application/json", r.Header.Get("Content-Type"))
			}

			var body struct {
				DeviceID string `json:"deviceId"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode request body: %v", err)
			}
			if body.DeviceID != id.DeviceID {
				t.Errorf("deviceId = %q, want %q", body.DeviceID, id.DeviceID)
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"nonce":"server-issued-nonce"}`))
		}))
		defer server.Close()

		nonce, err := fetchChallenge(id.DeviceID, server.URL, server.Client(), "")
		if err != nil {
			t.Fatalf("fetchChallenge() error: %v", err)
		}
		if nonce != "server-issued-nonce" {
			t.Errorf("nonce = %q, want %q", nonce, "server-issued-nonce")
		}
	})

	t.Run("error on empty nonce", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"nonce":""}`))
		}))
		defer server.Close()

		_, err := fetchChallenge(id.DeviceID, server.URL, server.Client(), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "empty nonce") {
			t.Errorf("error = %q, want substring %q", err.Error(), "empty nonce")
		}
	})

	t.Run("error on server error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal error"}`))
		}))
		defer server.Close()

		_, err := fetchChallenge(id.DeviceID, server.URL, server.Client(), "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), "server error (500)") {
			t.Errorf("error = %q, want substring %q", err.Error(), "server error (500)")
		}
	})

	t.Run("network error", func(t *testing.T) {
		_, err := fetchChallenge(id.DeviceID, "http://localhost:1", http.DefaultClient, "")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
