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
