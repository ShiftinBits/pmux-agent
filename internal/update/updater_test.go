package update

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestNewUpdater_AllMethods(t *testing.T) {
	methods := []struct {
		method InstallMethod
		desc   string
	}{
		{MethodHomebrew, "Homebrew"},
		{MethodSnap, "Snap"},
		{MethodDeb, "Debian"},
		{MethodRPM, "RPM"},
		{MethodGitHub, "GitHub"},
		{MethodDev, "development"},
	}

	for _, tt := range methods {
		t.Run(string(tt.method), func(t *testing.T) {
			u := NewUpdater(tt.method, "1.0.0", testLogger())
			if u == nil {
				t.Fatalf("NewUpdater(%q) returned nil", tt.method)
			}
			desc := u.Description()
			if desc == "" {
				t.Error("Description() returned empty string")
			}
		})
	}
}

func TestDevUpdater_ReturnsError(t *testing.T) {
	u := NewUpdater(MethodDev, "dev", testLogger())
	err := u.Update(ReleaseInfo{})
	if err == nil {
		t.Error("dev updater should return error")
	}
}

func TestFindAsset(t *testing.T) {
	release := ReleaseInfo{
		TagName: "v1.0.0",
		Assets: []ReleaseAsset{
			{Name: "pmux_1.0.0_linux_amd64.deb", BrowserDownloadURL: "https://example.com/pmux.deb"},
			{Name: "pmux_1.0.0_linux_arm64.deb", BrowserDownloadURL: "https://example.com/pmux-arm.deb"},
			{Name: "pmux_1.0.0_linux_amd64.rpm", BrowserDownloadURL: "https://example.com/pmux.rpm"},
		},
	}

	tests := []struct {
		name    string
		suffix  string
		arch    string
		wantURL string
		wantErr bool
	}{
		{"deb amd64", ".deb", "amd64", "https://example.com/pmux.deb", false},
		{"deb arm64", ".deb", "arm64", "https://example.com/pmux-arm.deb", false},
		{"rpm amd64", ".rpm", "amd64", "https://example.com/pmux.rpm", false},
		{"missing", ".deb", "mips", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset, err := findAsset(release, tt.suffix, tt.arch)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("findAsset() error: %v", err)
			}
			if asset.BrowserDownloadURL != tt.wantURL {
				t.Errorf("URL = %q, want %q", asset.BrowserDownloadURL, tt.wantURL)
			}
		})
	}
}

func TestGithubUpdater_MatchArchiveName(t *testing.T) {
	release := ReleaseInfo{
		TagName: "v1.2.3",
		Assets: []ReleaseAsset{
			{Name: "pmux-agent_1.2.3_Linux_x86_64.tar.gz"},
			{Name: "pmux-agent_1.2.3_Linux_arm64.tar.gz"},
			{Name: "pmux-agent_1.2.3_Darwin_universal.zip"},
			{Name: "checksums.txt"},
		},
	}

	u := &githubUpdater{current: "1.0.0", logger: testLogger()}
	name, err := u.matchArchiveName(release)
	if err != nil {
		t.Fatalf("matchArchiveName() error: %v", err)
	}
	// On macOS test runner, expect darwin_all.zip; on Linux, expect linux_<arch>.tar.gz
	if name == "" {
		t.Error("expected non-empty archive name")
	}
}

// makeTarGz creates a tar.gz archive in memory containing a single file.
func makeTarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name:     name,
		Size:     int64(len(content)),
		Mode:     0755,
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("tar header: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("tar write: %v", err)
	}
	tw.Close()
	gw.Close()
	return buf.Bytes()
}

// makeZip creates a zip archive in memory containing a single file.
func makeZip(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	fw, err := zw.Create(name)
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	zw.Close()
	return buf.Bytes()
}

func TestGithubUpdater_ExtractFromTarGz(t *testing.T) {
	u := &githubUpdater{current: "1.0.0", logger: testLogger()}
	binary := []byte("#!/bin/sh\necho hello")

	tests := []struct {
		name    string
		archive []byte
		wantErr string
	}{
		{
			name:    "extracts pmux binary",
			archive: makeTarGz(t, "pmux-agent_1.0.0_Linux_x86_64/pmux", binary),
		},
		{
			name:    "extracts pmux at root",
			archive: makeTarGz(t, "pmux", binary),
		},
		{
			name:    "missing pmux binary",
			archive: makeTarGz(t, "other-file", binary),
			wantErr: "pmux binary not found",
		},
		{
			name:    "invalid gzip",
			archive: []byte("not a gzip"),
			wantErr: "open gzip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := u.extractFromTarGz(tt.archive)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractFromTarGz() error: %v", err)
			}
			if !bytes.Equal(got, binary) {
				t.Errorf("extracted = %q, want %q", got, binary)
			}
		})
	}
}

func TestGithubUpdater_ExtractFromZip(t *testing.T) {
	u := &githubUpdater{current: "1.0.0", logger: testLogger()}
	binary := []byte("#!/bin/sh\necho hello")

	tests := []struct {
		name    string
		archive []byte
		wantErr string
	}{
		{
			name:    "extracts pmux binary",
			archive: makeZip(t, "pmux-agent_1.0.0_Darwin_universal/pmux", binary),
		},
		{
			name:    "extracts pmux at root",
			archive: makeZip(t, "pmux", binary),
		},
		{
			name:    "missing pmux binary",
			archive: makeZip(t, "other-file", binary),
			wantErr: "pmux binary not found in zip",
		},
		{
			name:    "invalid zip",
			archive: []byte("not a zip"),
			wantErr: "open zip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := u.extractFromZip(tt.archive)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractFromZip() error: %v", err)
			}
			if !bytes.Equal(got, binary) {
				t.Errorf("extracted = %q, want %q", got, binary)
			}
		})
	}
}

func TestGithubUpdater_ExtractBinary(t *testing.T) {
	u := &githubUpdater{current: "1.0.0", logger: testLogger()}
	binary := []byte("test-pmux-binary")

	tests := []struct {
		name        string
		archiveName string
		archive     []byte
	}{
		{
			name:        "zip archive",
			archiveName: "pmux-agent_1.0.0_Darwin_universal.zip",
			archive:     makeZip(t, "pmux", binary),
		},
		{
			name:        "tar.gz archive",
			archiveName: "pmux-agent_1.0.0_Linux_x86_64.tar.gz",
			archive:     makeTarGz(t, "pmux", binary),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := u.extractBinary(tt.archive, tt.archiveName)
			if err != nil {
				t.Fatalf("extractBinary() error: %v", err)
			}
			if !bytes.Equal(got, binary) {
				t.Errorf("extracted = %q, want %q", got, binary)
			}
		})
	}
}

func TestGithubUpdater_FetchExpectedChecksum(t *testing.T) {
	archiveName := "pmux-agent_1.0.0_Linux_x86_64.tar.gz"
	expectedHash := "abc123def456"
	checksums := fmt.Sprintf("%s  %s\nother_hash  other-file.tar.gz\n", expectedHash, archiveName)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksums))
	}))
	defer srv.Close()

	// Patch allowedDownloadHosts for test
	origHosts := allowedDownloadHosts
	allowedDownloadHosts = map[string]bool{srv.Listener.Addr().String(): true}
	defer func() { allowedDownloadHosts = origHosts }()

	u := &githubUpdater{current: "1.0.0", logger: testLogger()}

	// Use a transport that accepts the test server's TLS cert
	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	t.Run("found", func(t *testing.T) {
		hash, err := u.fetchExpectedChecksum("https://"+srv.Listener.Addr().String()+"/checksums.txt", archiveName)
		if err != nil {
			t.Fatalf("fetchExpectedChecksum() error: %v", err)
		}
		if hash != expectedHash {
			t.Errorf("hash = %q, want %q", hash, expectedHash)
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := u.fetchExpectedChecksum("https://"+srv.Listener.Addr().String()+"/checksums.txt", "nonexistent.tar.gz")
		if err == nil {
			t.Fatal("expected error for missing checksum")
		}
		if !strings.Contains(err.Error(), "no checksum found") {
			t.Errorf("error %q does not contain 'no checksum found'", err.Error())
		}
	})
}

func testArchiveName(version string) (name string, ext string) {
	osName := strings.ToUpper(runtime.GOOS[:1]) + runtime.GOOS[1:]
	archSuffix := runtime.GOARCH
	switch {
	case runtime.GOOS == "darwin":
		archSuffix = "universal"
	case runtime.GOARCH == "amd64":
		archSuffix = "x86_64"
	}
	if runtime.GOOS == "darwin" {
		ext = ".zip"
	} else {
		ext = ".tar.gz"
	}
	return fmt.Sprintf("pmux-agent_%s_%s_%s%s", version, osName, archSuffix, ext), ext
}

func TestGithubUpdater_Update_ChecksumMismatch(t *testing.T) {
	binary := []byte("fake-pmux-binary")
	archiveName, ext := testArchiveName("1.0.0")

	var archiveData []byte
	if ext == ".zip" {
		archiveData = makeZip(t, "pmux", binary)
	} else {
		archiveData = makeTarGz(t, "pmux", binary)
	}

	// Compute real checksum, then serve a wrong one.
	realHash := sha256.Sum256(archiveData)
	wrongHash := "0000000000000000000000000000000000000000000000000000000000000000"
	if wrongHash == hex.EncodeToString(realHash[:]) {
		wrongHash = "1111111111111111111111111111111111111111111111111111111111111111"
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "checksums") {
			fmt.Fprintf(w, "%s  %s\n", wrongHash, archiveName)
			return
		}
		w.Write(archiveData)
	}))
	defer srv.Close()

	origHosts := allowedDownloadHosts
	allowedDownloadHosts = map[string]bool{srv.Listener.Addr().String(): true}
	defer func() { allowedDownloadHosts = origHosts }()

	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	u := &githubUpdater{current: "1.0.0", logger: testLogger()}
	release := ReleaseInfo{
		TagName: "v1.0.0",
		Assets: []ReleaseAsset{
			{Name: archiveName, BrowserDownloadURL: "https://" + srv.Listener.Addr().String() + "/archive"},
			{Name: "checksums.txt", BrowserDownloadURL: "https://" + srv.Listener.Addr().String() + "/checksums"},
		},
	}

	err := u.Update(release)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error %q does not contain 'checksum mismatch'", err.Error())
	}
}

func TestGithubUpdater_Update_MissingAsset(t *testing.T) {
	u := &githubUpdater{current: "1.0.0", logger: testLogger()}

	t.Run("missing archive asset", func(t *testing.T) {
		release := ReleaseInfo{
			TagName: "v1.0.0",
			Assets: []ReleaseAsset{
				{Name: "checksums.txt", BrowserDownloadURL: "https://github.com/checksums"},
			},
		}
		err := u.Update(release)
		if err == nil {
			t.Fatal("expected error for missing archive")
		}
	})

	t.Run("missing checksums asset", func(t *testing.T) {
		release := ReleaseInfo{
			TagName: "v1.0.0",
			Assets:  []ReleaseAsset{},
		}
		err := u.Update(release)
		if err == nil {
			t.Fatal("expected error for missing assets")
		}
	})
}

func TestGithubUpdater_Download_Success(t *testing.T) {
	body := []byte("file-content")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	origHosts := allowedDownloadHosts
	allowedDownloadHosts = map[string]bool{srv.Listener.Addr().String(): true}
	defer func() { allowedDownloadHosts = origHosts }()

	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	u := &githubUpdater{current: "1.0.0", logger: testLogger()}
	got, err := u.download("https://"+srv.Listener.Addr().String()+"/file", 1024)
	if err != nil {
		t.Fatalf("download() error: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("download() = %q, want %q", got, body)
	}
}

func TestGithubUpdater_Download_HTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	origHosts := allowedDownloadHosts
	allowedDownloadHosts = map[string]bool{srv.Listener.Addr().String(): true}
	defer func() { allowedDownloadHosts = origHosts }()

	origTransport := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = origTransport }()

	u := &githubUpdater{current: "1.0.0", logger: testLogger()}
	_, err := u.download("https://"+srv.Listener.Addr().String()+"/file", 1024)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("error %q does not contain 'HTTP 500'", err.Error())
	}
}

func TestDebUpdater_Update(t *testing.T) {
	u := &debUpdater{logger: testLogger()}
	release := ReleaseInfo{
		TagName: "v1.0.0",
		Assets: []ReleaseAsset{
			{Name: fmt.Sprintf("pmux_1.0.0_linux_%s.deb", runtime.GOARCH), BrowserDownloadURL: "https://example.com/pmux.deb"},
		},
	}

	// deb updater just prints instructions, should not error with matching asset
	err := u.Update(release)
	if err != nil {
		t.Errorf("debUpdater.Update() error: %v", err)
	}
}

func TestDebUpdater_Update_MissingAsset(t *testing.T) {
	u := &debUpdater{logger: testLogger()}
	release := ReleaseInfo{TagName: "v1.0.0", Assets: []ReleaseAsset{}}

	err := u.Update(release)
	if err == nil {
		t.Error("expected error for missing asset")
	}
}

func TestRPMUpdater_Update(t *testing.T) {
	u := &rpmUpdater{logger: testLogger()}
	release := ReleaseInfo{
		TagName: "v1.0.0",
		Assets: []ReleaseAsset{
			{Name: fmt.Sprintf("pmux_1.0.0_linux_%s.rpm", runtime.GOARCH), BrowserDownloadURL: "https://example.com/pmux.rpm"},
		},
	}

	err := u.Update(release)
	if err != nil {
		t.Errorf("rpmUpdater.Update() error: %v", err)
	}
}

func TestRPMUpdater_Update_MissingAsset(t *testing.T) {
	u := &rpmUpdater{logger: testLogger()}
	release := ReleaseInfo{TagName: "v1.0.0", Assets: []ReleaseAsset{}}

	err := u.Update(release)
	if err == nil {
		t.Error("expected error for missing asset")
	}
}

func TestSnapUpdater_Update(t *testing.T) {
	u := &snapUpdater{logger: testLogger()}

	// Snap updater always returns nil (just prints instructions)
	err := u.Update(ReleaseInfo{})
	if err != nil {
		t.Errorf("snapUpdater.Update() error: %v", err)
	}
}

func TestHomebrewUpdater_Update_NoBrew(t *testing.T) {
	// When brew is not in PATH, Update should return an error.
	// Temporarily clear PATH to ensure brew can't be found.
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir()) // empty directory

	u := &homebrewUpdater{logger: testLogger()}
	err := u.Update(ReleaseInfo{})
	if err == nil {
		t.Error("expected error when brew not in PATH")
	}
	if !strings.Contains(err.Error(), "brew not found") {
		t.Errorf("error %q does not contain 'brew not found'", err.Error())
	}

	_ = origPath // restored by t.Setenv cleanup
}

func TestErrElevationRequired_Error(t *testing.T) {
	err := &ErrElevationRequired{Command: "sudo dpkg -i pmux.deb"}
	got := err.Error()
	if !strings.Contains(got, "sudo dpkg -i pmux.deb") {
		t.Errorf("Error() = %q, want to contain command", got)
	}
}

func TestChecker_FetchRelease_Success(t *testing.T) {
	release := ReleaseInfo{
		TagName: "v2.0.0",
		HTMLURL: "https://github.com/test/repo/releases/tag/v2.0.0",
		Assets: []ReleaseAsset{
			{Name: "pmux-agent.tar.gz", BrowserDownloadURL: "https://github.com/test/repo/releases/download/v2.0.0/pmux-agent.tar.gz"},
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(release)
	})

	c := newTestChecker(t, "1.0.0", handler)
	got, err := c.FetchRelease()
	if err != nil {
		t.Fatalf("FetchRelease() error: %v", err)
	}
	if got.TagName != "v2.0.0" {
		t.Errorf("TagName = %q, want %q", got.TagName, "v2.0.0")
	}
	if len(got.Assets) != 1 {
		t.Errorf("Assets count = %d, want 1", len(got.Assets))
	}
}

func TestGithubUpdater_DownloadRejectsUntrustedURLs(t *testing.T) {
	u := &githubUpdater{current: "1.0.0", logger: testLogger()}

	tests := []struct {
		name    string
		url     string
		wantErr string
	}{
		{"evil host", "https://evil.com/payload", "untrusted download URL"},
		{"http scheme", "http://github.com/file", "untrusted download URL"},
		{"ftp scheme", "ftp://github.com/file", "untrusted download URL"},
		{"no scheme", "github.com/file", "untrusted download URL"},
		{"empty url", "", "untrusted download URL"},
		{"valid github host", "https://github.com/some/release", ""},
		{"valid githubusercontent host", "https://objects.githubusercontent.com/file", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := u.download(tt.url, 1024)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			} else {
				// Valid URLs may fail with network errors, but should NOT fail with untrusted URL error.
				if err != nil && strings.Contains(err.Error(), "untrusted download URL") {
					t.Errorf("valid URL %q was rejected as untrusted: %v", tt.url, err)
				}
			}
		})
	}
}
