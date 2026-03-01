package service

import (
	"runtime"
	"testing"
)

func TestNewManager_ReturnsPlatformManager(t *testing.T) {
	mgr := NewManager("/usr/local/bin/pmux", "/tmp/test-config")
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}

	switch runtime.GOOS {
	case "darwin":
		if _, ok := mgr.(*launchdManager); !ok {
			t.Errorf("expected launchdManager on darwin, got %T", mgr)
		}
	case "linux":
		if _, ok := mgr.(*systemdManager); !ok {
			t.Errorf("expected systemdManager on linux, got %T", mgr)
		}
	default:
		if _, ok := mgr.(*unsupportedManager); !ok {
			t.Errorf("expected unsupportedManager on %s, got %T", runtime.GOOS, mgr)
		}
	}
}

func TestUnsupportedManager_AllMethodsReturnError(t *testing.T) {
	mgr := &unsupportedManager{platform: "plan9"}

	if err := mgr.Install(); err == nil {
		t.Error("Install should return error")
	}
	if err := mgr.Uninstall(); err == nil {
		t.Error("Uninstall should return error")
	}
	if err := mgr.Start(); err == nil {
		t.Error("Start should return error")
	}
	if err := mgr.Stop(); err == nil {
		t.Error("Stop should return error")
	}
	if _, err := mgr.Status(); err == nil {
		t.Error("Status should return error")
	}
}

func TestUnsupportedManager_IsInstalledReturnsFalse(t *testing.T) {
	mgr := &unsupportedManager{}
	if mgr.IsInstalled() {
		t.Error("expected IsInstalled to return false")
	}
}
