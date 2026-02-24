package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/shiftinbits/pmux-agent/internal/config"
)

func TestPIDFilePath(t *testing.T) {
	paths := config.Paths{ConfigDir: "/tmp/test-pmux"}
	got := PIDFilePath(paths)
	want := "/tmp/test-pmux/agent.pid"
	if got != want {
		t.Errorf("PIDFilePath = %q, want %q", got, want)
	}
}

func TestEnsureRunning_NoIdentity(t *testing.T) {
	dir := t.TempDir()
	paths := config.Paths{
		ConfigDir: dir,
		KeysDir:   filepath.Join(dir, "keys"),
	}

	// No identity exists — EnsureRunning should be a no-op
	err := EnsureRunning(paths)
	if err != nil {
		t.Errorf("EnsureRunning should not error without identity: %v", err)
	}

	// No PID file should be created
	pidFile := filepath.Join(dir, pidFileName)
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("PID file should not exist when no identity")
	}
}
