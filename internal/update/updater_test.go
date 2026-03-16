package update

import (
	"log/slog"
	"os"
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
			{Name: "pmux_1.2.3_linux_amd64.tar.gz"},
			{Name: "pmux_1.2.3_linux_arm64.tar.gz"},
			{Name: "pmux_1.2.3_darwin_all.zip"},
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
