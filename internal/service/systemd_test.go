//go:build linux

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdManager_UnitPath(t *testing.T) {
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	path := mgr.unitPath()
	if !strings.HasSuffix(path, ".config/systemd/user/pmux-agent.service") {
		t.Errorf("unexpected unit path: %s", path)
	}
}

func TestSystemdManager_GenerateUnit(t *testing.T) {
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	unit := mgr.generateUnit()

	if !strings.Contains(unit, "ExecStart=/usr/local/bin/pmux agent run") {
		t.Error("unit missing ExecStart")
	}
	if !strings.Contains(unit, "Restart=on-failure") {
		t.Error("unit missing restart policy")
	}
	if !strings.Contains(unit, "RestartSec=5s") {
		t.Error("unit missing restart delay")
	}
	if !strings.Contains(unit, "StandardOutput=append:") {
		t.Error("unit missing StandardOutput")
	}
	if !strings.Contains(unit, "StandardError=append:") {
		t.Error("unit missing StandardError")
	}
}

func TestSystemdManager_Install_WritesUnit(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = tmpDir

	if err := mgr.writeUnit(); err != nil {
		t.Fatalf("writeUnit: %v", err)
	}

	path := filepath.Join(tmpDir, "pmux-agent.service")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read unit: %v", err)
	}

	if !strings.Contains(string(data), "PocketMux Agent") {
		t.Error("written unit missing description")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat unit: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("unit file permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestSystemdManager_IsInstalled(t *testing.T) {
	tmpDir := t.TempDir()
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = tmpDir

	if mgr.IsInstalled() {
		t.Error("should not be installed before writing unit")
	}

	if err := mgr.writeUnit(); err != nil {
		t.Fatalf("writeUnit: %v", err)
	}

	if !mgr.IsInstalled() {
		t.Error("should be installed after writing unit")
	}
}
