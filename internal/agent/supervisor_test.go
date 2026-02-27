package agent

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/config"
)

func TestPIDFilePath(t *testing.T) {
	paths := config.Paths{ConfigDir: "/tmp/test-pmux"}
	got := PIDFilePath(paths)
	want := "/tmp/test-pmux/host.pid"
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

func TestSignalActivity_DeliversSIGUSR1(t *testing.T) {
	// Register to receive SIGUSR1 on the current process
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	defer signal.Stop(ch)

	signalActivity(os.Getpid())

	select {
	case sig := <-ch:
		if sig != syscall.SIGUSR1 {
			t.Errorf("received %v, want SIGUSR1", sig)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SIGUSR1")
	}
}

func TestSignalActivity_NonexistentPID(t *testing.T) {
	// Should not panic when sending to a PID that doesn't exist.
	// Use a very high PID unlikely to be in use.
	signalActivity(999999999)
}

func TestStopRunning_NoAgent(t *testing.T) {
	dir := t.TempDir()
	paths := config.Paths{ConfigDir: dir}

	// No PID file — StopRunning should return nil
	if err := StopRunning(paths); err != nil {
		t.Errorf("StopRunning with no agent should return nil: %v", err)
	}
}

func TestStopRunning_StalePID(t *testing.T) {
	dir := t.TempDir()
	paths := config.Paths{ConfigDir: dir}

	// Write a PID file for a process that doesn't exist
	pidFile := PIDFilePath(paths)
	os.WriteFile(pidFile, []byte("999999999"), pidFilePerms)

	if err := StopRunning(paths); err != nil {
		t.Errorf("StopRunning with stale PID should return nil: %v", err)
	}

	// PID file should be cleaned up
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("stale PID file should be removed after StopRunning")
	}
}
