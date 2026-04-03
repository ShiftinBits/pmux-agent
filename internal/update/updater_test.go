package update

import (
	"log/slog"
	"os"
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
