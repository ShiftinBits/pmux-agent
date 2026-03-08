package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDeletePairing_Success(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/token" && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt"}`))
		case r.URL.Path == "/auth/pairing" && r.Method == "DELETE":
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-jwt" {
				t.Errorf("unexpected Authorization header: %s", auth)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	if err := DeletePairing(id, server.URL, server.Client()); err != nil {
		t.Fatalf("DeletePairing() error: %v", err)
	}
}

func TestDeletePairing_ServerError(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt"}`))
		case r.URL.Path == "/auth/pairing":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal error"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	err = DeletePairing(id, server.URL, server.Client())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "server error (500)") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server error (500)")
	}
}

func TestDeletePairing_TokenExchangeFailure(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid signature"}`))
	}))
	defer server.Close()

	err = DeletePairing(id, server.URL, server.Client())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "token exchange") {
		t.Errorf("error = %q, want substring %q", err.Error(), "token exchange")
	}
}

func TestDeleteDevice_Success(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/token" && r.Method == "POST":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt"}`))
		case r.URL.Path == "/auth/device" && r.Method == "DELETE":
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-jwt" {
				t.Errorf("unexpected Authorization header: %s", auth)
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	if err := DeleteDevice(id, server.URL, server.Client()); err != nil {
		t.Fatalf("DeleteDevice() error: %v", err)
	}
}

func TestDeleteDevice_ServerError(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/auth/token":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"token":"test-jwt"}`))
		case r.URL.Path == "/auth/device":
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"error":"internal error"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	err = DeleteDevice(id, server.URL, server.Client())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "server error (500)") {
		t.Errorf("error = %q, want substring %q", err.Error(), "server error (500)")
	}
}

func TestDeleteDevice_TokenExchangeFailure(t *testing.T) {
	keysDir := t.TempDir()
	store := NewMemorySecretStore()
	id, err := GenerateIdentity(keysDir, store)
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid signature"}`))
	}))
	defer server.Close()

	err = DeleteDevice(id, server.URL, server.Client())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "token exchange") {
		t.Errorf("error = %q, want substring %q", err.Error(), "token exchange")
	}
}
