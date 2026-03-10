package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExchangeToken(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity() error: %v", err)
	}

	t.Run("successful token exchange", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/auth/token" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("unexpected method: %s", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected content type: %s", r.Header.Get("Content-Type"))
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

	t.Run("server returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
