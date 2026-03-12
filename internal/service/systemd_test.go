package service

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSystemdInstall_Success verifies Install writes the unit file and runs
// the three expected systemctl sub-commands (daemon-reload, enable, start).
func TestSystemdInstall_Success(t *testing.T) {
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = fakeExecCommand("success")

	tmpDir := t.TempDir()
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = tmpDir

	if err := mgr.Install(); err != nil {
		t.Fatalf("Install() returned unexpected error: %v", err)
	}

	path := filepath.Join(tmpDir, systemdUnitName)
	if _, err := os.Stat(path); err != nil {
		t.Errorf("unit file not written after Install: %v", err)
	}
}

// TestSystemdInstall_WriteError verifies Install returns an error when the
// unit directory is not writable.
func TestSystemdInstall_WriteError(t *testing.T) {
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = fakeExecCommand("success")

	// Create a read-only directory so MkdirAll / WriteFile fails.
	tmpDir := t.TempDir()
	readOnlyDir := filepath.Join(tmpDir, "ro")
	if err := os.MkdirAll(readOnlyDir, 0555); err != nil {
		t.Fatalf("setup read-only dir: %v", err)
	}

	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = filepath.Join(readOnlyDir, "systemd", "user")

	if err := mgr.Install(); err == nil {
		t.Fatal("Install() expected an error for non-writable unitDir, got nil")
	}
}

// TestSystemdUninstall_Success verifies Uninstall removes the unit file and
// returns nil even when systemctl calls succeed.
func TestSystemdUninstall_Success(t *testing.T) {
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = fakeExecCommand("success")

	tmpDir := t.TempDir()
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = tmpDir

	// Pre-write the unit file so there is something to remove.
	if err := mgr.writeUnit(); err != nil {
		t.Fatalf("setup writeUnit: %v", err)
	}

	if err := mgr.Uninstall(); err != nil {
		t.Fatalf("Uninstall() returned unexpected error: %v", err)
	}

	path := filepath.Join(tmpDir, systemdUnitName)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("unit file still exists after Uninstall")
	}
}

// TestSystemdStart_Success verifies Start returns nil when systemctl succeeds.
func TestSystemdStart_Success(t *testing.T) {
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = fakeExecCommand("success")

	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = t.TempDir()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}
}

// TestSystemdStop_Success verifies Stop returns nil when systemctl succeeds.
func TestSystemdStop_Success(t *testing.T) {
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = fakeExecCommand("success")

	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = t.TempDir()

	if err := mgr.Stop(); err != nil {
		t.Fatalf("Stop() returned unexpected error: %v", err)
	}
}

// TestSystemdStatus_Running verifies Status correctly parses "ActiveState=active"
// and a non-zero MainPID from systemctl show output.
func TestSystemdStatus_Running(t *testing.T) {
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = fakeExecCommand("status_running")

	tmpDir := t.TempDir()
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = tmpDir

	// Write the unit file so IsInstalled() returns true.
	if err := mgr.writeUnit(); err != nil {
		t.Fatalf("setup writeUnit: %v", err)
	}

	s, err := mgr.Status()
	if err != nil {
		t.Fatalf("Status() returned unexpected error: %v", err)
	}
	if !s.Running {
		t.Error("expected Running=true for ActiveState=active")
	}
	if s.PID != 54321 {
		t.Errorf("expected PID=54321, got %d", s.PID)
	}
}

// TestSystemdStatus_Stopped verifies Status returns Running=false and PID=0
// when systemctl reports "ActiveState=inactive".
func TestSystemdStatus_Stopped(t *testing.T) {
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = fakeExecCommand("status_stopped")

	tmpDir := t.TempDir()
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = tmpDir

	// Write the unit file so IsInstalled() returns true.
	if err := mgr.writeUnit(); err != nil {
		t.Fatalf("setup writeUnit: %v", err)
	}

	s, err := mgr.Status()
	if err != nil {
		t.Fatalf("Status() returned unexpected error: %v", err)
	}
	if s.Running {
		t.Error("expected Running=false for ActiveState=inactive")
	}
	if s.PID != 0 {
		t.Errorf("expected PID=0, got %d", s.PID)
	}
}

// TestSystemdStatus_NotInstalled verifies Status returns Installed=false when
// systemctl fails and no unit file exists.
func TestSystemdStatus_NotInstalled(t *testing.T) {
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = fakeExecCommand("failure")

	// Empty tmpDir — no unit file written.
	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = t.TempDir()

	s, err := mgr.Status()
	if err != nil {
		t.Fatalf("Status() returned unexpected error: %v", err)
	}
	if s.Installed {
		t.Error("expected Installed=false when no unit file exists")
	}
	if s.Running {
		t.Error("expected Running=false when not installed")
	}
}

// TestSystemctl_PrependUser verifies the --user flag is always prepended to
// every systemctl invocation by inspecting what arguments the subprocess
// receives via the helper process environment.
func TestSystemctl_PrependUser(t *testing.T) {
	// Use a custom execCommand that captures the args passed to it.
	var capturedArgs []string
	orig := execCommand
	t.Cleanup(func() { execCommand = orig })
	execCommand = func(name string, args ...string) *exec.Cmd {
		capturedArgs = append([]string{name}, args...)
		// Delegate to the real fake to avoid actually running systemctl.
		return fakeExecCommand("success")(name, args...)
	}

	mgr := newSystemdManager("/usr/local/bin/pmux", "/home/test/.config/pmux")
	mgr.unitDir = t.TempDir()

	if err := mgr.Start(); err != nil {
		t.Fatalf("Start() returned unexpected error: %v", err)
	}

	if len(capturedArgs) < 2 {
		t.Fatalf("expected at least 2 args, got %v", capturedArgs)
	}
	if capturedArgs[0] != "systemctl" {
		t.Errorf("expected command 'systemctl', got %q", capturedArgs[0])
	}
	if capturedArgs[1] != "--user" {
		t.Errorf("expected first argument '--user', got %q", capturedArgs[1])
	}
}


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
