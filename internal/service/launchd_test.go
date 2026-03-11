//go:build darwin

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchdManager_PlistPath(t *testing.T) {
	mgr := newLaunchdManager("/usr/local/bin/pmux", "/Users/test/.config/pmux")
	path := mgr.plistPath()
	if !strings.HasSuffix(path, "Library/LaunchAgents/io.pmux.agent.plist") {
		t.Errorf("unexpected plist path: %s", path)
	}
}

func TestLaunchdManager_GeneratePlist(t *testing.T) {
	mgr := newLaunchdManager("/usr/local/bin/pmux", "/Users/test/.config/pmux")
	plist := mgr.generatePlist()

	if !strings.Contains(plist, "<string>io.pmux.agent</string>") {
		t.Error("plist missing label")
	}
	if !strings.Contains(plist, "<string>/usr/local/bin/pmux</string>") {
		t.Error("plist missing pmux path")
	}
	if !strings.Contains(plist, "<string>agent</string>") {
		t.Error("plist missing 'agent' argument")
	}
	if !strings.Contains(plist, "<string>run</string>") {
		t.Error("plist missing 'run' argument")
	}
	if !strings.Contains(plist, "agent.log") {
		t.Error("plist missing log path")
	}
}

func TestLaunchdManager_Install_WritesPlist(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := newLaunchdManager("/usr/local/bin/pmux", "/Users/test/.config/pmux")
	mgr.plistDir = tmpDir

	if err := mgr.writePlist(); err != nil {
		t.Fatalf("writePlist: %v", err)
	}

	path := filepath.Join(tmpDir, "io.pmux.agent.plist")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read plist: %v", err)
	}

	if !strings.Contains(string(data), "io.pmux.agent") {
		t.Error("written plist missing label")
	}
}

func TestLaunchdManager_IsInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := newLaunchdManager("/usr/local/bin/pmux", "/Users/test/.config/pmux")
	mgr.plistDir = tmpDir

	if mgr.IsInstalled() {
		t.Error("should not be installed before writing plist")
	}

	if err := mgr.writePlist(); err != nil {
		t.Fatalf("writePlist: %v", err)
	}

	if !mgr.IsInstalled() {
		t.Error("should be installed after writing plist")
	}
}

func TestLaunchctlHint(t *testing.T) {
	tests := []struct {
		name     string
		output   string
		exitCode int
		wantHint string // substring expected in hint; empty means no hint
	}{
		{
			name:     "domain does not support specified action",
			output:   "Bootstrap failed: 125: Domain does not support specified action",
			exitCode: 125,
			wantHint: "Run without sudo",
		},
		{
			name:     "case insensitive match",
			output:   "DOMAIN DOES NOT SUPPORT SPECIFIED ACTION",
			exitCode: 125,
			wantHint: "Run without sudo",
		},
		{
			name:     "could not find specified service",
			output:   "Could not find specified service",
			exitCode: 113,
			wantHint: "pmux agent install",
		},
		{
			name:     "operation not permitted",
			output:   "Operation not permitted",
			exitCode: 1,
			wantHint: "Permission denied",
		},
		{
			name:     "no such file or directory",
			output:   "No such file or directory",
			exitCode: 2,
			wantHint: "plist file is missing",
		},
		{
			name:     "exit 125 unknown message",
			output:   "some unknown error text",
			exitCode: 125,
			wantHint: "pmux agent uninstall && pmux agent install",
		},
		{
			name:     "no hint for generic error",
			output:   "some unknown error text",
			exitCode: 1,
			wantHint: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hint := launchctlHint(tt.output, tt.exitCode)
			if tt.wantHint == "" {
				if hint != "" {
					t.Errorf("expected no hint, got: %s", hint)
				}
			} else {
				if !strings.Contains(hint, tt.wantHint) {
					t.Errorf("hint %q does not contain %q", hint, tt.wantHint)
				}
			}
		})
	}
}

func TestCheckNotRoot_NonRoot(t *testing.T) {
	// This test runs as the current (non-root) user in normal test runs.
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}
	if err := checkNotRoot(); err != nil {
		t.Errorf("checkNotRoot should pass for non-root user: %v", err)
	}
}
