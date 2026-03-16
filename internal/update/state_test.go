package update

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStateFilePath(t *testing.T) {
	got := StateFilePath("/home/user/.config/pmux")
	want := "/home/user/.config/pmux/update-state.json"
	if got != want {
		t.Errorf("StateFilePath() = %q, want %q", got, want)
	}
}

func TestStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")

	want := State{
		LastCheck:       time.Date(2026, 3, 16, 10, 0, 0, 0, time.UTC),
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.1.0",
		UpdateAvailable: true,
		ReleaseURL:      "https://github.com/ShiftinBits/pmux-agent/releases/tag/v1.1.0",
		InstallMethod:   "homebrew",
		BinaryPath:      "/opt/homebrew/bin/pmux",
	}

	if err := SaveState(path, want); err != nil {
		t.Fatalf("SaveState() error: %v", err)
	}

	got, err := LoadState(path)
	if err != nil {
		t.Fatalf("LoadState() error: %v", err)
	}

	if got.CurrentVersion != want.CurrentVersion {
		t.Errorf("CurrentVersion = %q, want %q", got.CurrentVersion, want.CurrentVersion)
	}
	if got.LatestVersion != want.LatestVersion {
		t.Errorf("LatestVersion = %q, want %q", got.LatestVersion, want.LatestVersion)
	}
	if got.UpdateAvailable != want.UpdateAvailable {
		t.Errorf("UpdateAvailable = %v, want %v", got.UpdateAvailable, want.UpdateAvailable)
	}
	if got.ReleaseURL != want.ReleaseURL {
		t.Errorf("ReleaseURL = %q, want %q", got.ReleaseURL, want.ReleaseURL)
	}
	if got.InstallMethod != want.InstallMethod {
		t.Errorf("InstallMethod = %q, want %q", got.InstallMethod, want.InstallMethod)
	}
	if got.BinaryPath != want.BinaryPath {
		t.Errorf("BinaryPath = %q, want %q", got.BinaryPath, want.BinaryPath)
	}
	if !got.LastCheck.Equal(want.LastCheck) {
		t.Errorf("LastCheck = %v, want %v", got.LastCheck, want.LastCheck)
	}
}

func TestLoadState_FileNotExist(t *testing.T) {
	state, err := LoadState("/nonexistent/path/update-state.json")
	if err != nil {
		t.Fatalf("LoadState() error: %v, want nil", err)
	}
	if state.UpdateAvailable {
		t.Error("expected zero State with UpdateAvailable=false")
	}
}

func TestLoadState_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")
	if err := os.WriteFile(path, []byte("not json{{{"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadState(path)
	if err == nil {
		t.Error("LoadState() expected error for corrupt file, got nil")
	}
}

func TestSaveState_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")

	if err := SaveState(path, State{CurrentVersion: "1.0.0"}); err != nil {
		t.Fatalf("SaveState() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}
