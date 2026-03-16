package update

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newTestChecker(t *testing.T, version string, handler http.Handler) *Checker {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	c := NewChecker(version, filepath.Join(dir, "update-state.json"), testLogger())
	c.repo = "test/repo"
	c.httpClient = srv.Client()
	// Override the URL by replacing the repo with the test server path.
	// We need to override FetchRelease to use the test server URL.
	// Simpler: just override the httpClient and intercept the request.
	// Actually, let's use a custom transport.
	c.httpClient.Transport = &rewriteTransport{
		base:    srv.Client().Transport,
		baseURL: srv.URL,
	}
	return c
}

// rewriteTransport redirects all requests to the test server.
type rewriteTransport struct {
	base    http.RoundTripper
	baseURL string
}

func (t *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.baseURL[len("http://"):]
	if t.base == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return t.base.RoundTrip(req)
}

func TestChecker_NewerVersionAvailable(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release := ReleaseInfo{
			TagName: "v2.0.0",
			HTMLURL: "https://github.com/test/repo/releases/tag/v2.0.0",
		}
		json.NewEncoder(w).Encode(release)
	})

	c := newTestChecker(t, "1.0.0", handler)
	state, err := c.Check(MethodGitHub)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !state.UpdateAvailable {
		t.Error("expected UpdateAvailable=true")
	}
	if state.LatestVersion != "v2.0.0" {
		t.Errorf("LatestVersion = %q, want %q", state.LatestVersion, "v2.0.0")
	}
}

func TestChecker_AlreadyCurrent(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release := ReleaseInfo{TagName: "v1.0.0"}
		json.NewEncoder(w).Encode(release)
	})

	c := newTestChecker(t, "1.0.0", handler)
	state, err := c.Check(MethodGitHub)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if state.UpdateAvailable {
		t.Error("expected UpdateAvailable=false for same version")
	}
}

func TestChecker_DevVersion(t *testing.T) {
	// Should not make any HTTP request.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unexpected HTTP request for dev version")
	})

	c := newTestChecker(t, "dev", handler)
	state, err := c.Check(MethodDev)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if state.UpdateAvailable {
		t.Error("dev version should never have update available")
	}
}

func TestChecker_RateLimit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	c := newTestChecker(t, "1.0.0", handler)
	_, err := c.Check(MethodGitHub)
	if err == nil {
		t.Error("expected error for rate-limited response")
	}
}

func TestChecker_NotFound(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	c := newTestChecker(t, "1.0.0", handler)
	_, err := c.Check(MethodGitHub)
	if err == nil {
		t.Error("expected error for 404 response")
	}
}

func TestChecker_PersistsState(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		release := ReleaseInfo{
			TagName: "v2.0.0",
			HTMLURL: "https://example.com/release",
		}
		json.NewEncoder(w).Encode(release)
	})

	c := newTestChecker(t, "1.0.0", handler)
	_, err := c.Check(MethodHomebrew)
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}

	// Read back the persisted state.
	state, err := LoadState(c.stateFile)
	if err != nil {
		t.Fatalf("LoadState() error: %v", err)
	}
	if !state.UpdateAvailable {
		t.Error("persisted state should have UpdateAvailable=true")
	}
	if state.InstallMethod != "homebrew" {
		t.Errorf("InstallMethod = %q, want %q", state.InstallMethod, "homebrew")
	}
}
