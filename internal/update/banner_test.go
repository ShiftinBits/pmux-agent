package update

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrintBannerIfAvailable_UpdateAvailable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")

	state := State{
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.1.0",
		UpdateAvailable: true,
	}
	if err := SaveState(path, state); err != nil {
		t.Fatal(err)
	}

	// Capture stderr output.
	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	PrintBannerIfAvailable(path)

	w.Close()
	os.Stderr = old

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if output == "" {
		t.Error("expected banner output, got empty string")
	}
	if !strings.Contains(output, "1.0.0") || !strings.Contains(output, "1.1.0") {
		t.Errorf("banner should contain version numbers, got: %q", output)
	}
	if !strings.Contains(output, "pmux update") {
		t.Errorf("banner should mention 'pmux update', got: %q", output)
	}
}

func TestPrintBannerIfAvailable_NoBanner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update-state.json")

	state := State{
		CurrentVersion:  "1.0.0",
		LatestVersion:   "1.0.0",
		UpdateAvailable: false,
	}
	if err := SaveState(path, state); err != nil {
		t.Fatal(err)
	}

	old := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	PrintBannerIfAvailable(path)

	w.Close()
	os.Stderr = old

	buf := make([]byte, 1024)
	n, _ := r.Read(buf)
	if n > 0 {
		t.Errorf("expected no banner output, got: %q", string(buf[:n]))
	}
}

func TestPrintBannerIfAvailable_NoFile(t *testing.T) {
	// Should not panic or error — just silently do nothing.
	PrintBannerIfAvailable("/nonexistent/path/update-state.json")
}
