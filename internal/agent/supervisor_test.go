package agent

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/auth"
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

	store := auth.NewMemorySecretStore()

	// No identity exists — EnsureRunning should be a no-op
	err := EnsureRunning(paths, store, nil)
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

func TestSignalUnpair_DeliversSIGUSR2(t *testing.T) {
	// Register to receive SIGUSR2 on the current process
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	defer signal.Stop(ch)

	signalReloadPairing(os.Getpid())

	select {
	case sig := <-ch:
		if sig != syscall.SIGUSR2 {
			t.Errorf("received %v, want SIGUSR2", sig)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SIGUSR2")
	}
}

func TestWaitForPID_Found(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, pidFileName)

	// Write the PID file after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		if err := WritePIDFile(pidFile); err != nil {
			// Can't call t.Fatal from a goroutine; the timeout will catch this
			return
		}
	}()

	if !waitForPID(pidFile, 500*time.Millisecond) {
		t.Error("waitForPID should return true when PID file is written with a running process")
	}
}

func TestWaitForPID_Timeout(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "nonexistent.pid")

	// No PID file will ever appear — expect timeout
	if waitForPID(pidFile, 200*time.Millisecond) {
		t.Error("waitForPID should return false when PID file never appears")
	}
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

func TestEnsureRunning_FlockSerializesConcurrentCallers(t *testing.T) {
	// Verify that flock on the PID file serializes concurrent access.
	// We simulate the EnsureRunning locking pattern: open the PID file,
	// acquire LOCK_EX, do work inside the critical section, then release.
	// With 10 concurrent goroutines, at most 1 should be in the critical
	// section at any time.

	dir := t.TempDir()
	pidFile := filepath.Join(dir, pidFileName)

	const goroutines = 10
	var (
		wg         sync.WaitGroup
		maxInside  atomic.Int32
		curInside  atomic.Int32
		lockErrors atomic.Int32
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()

			f, err := os.OpenFile(pidFile, os.O_CREATE|os.O_RDWR, pidFilePerms)
			if err != nil {
				lockErrors.Add(1)
				return
			}
			defer f.Close()

			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
				lockErrors.Add(1)
				return
			}

			// Inside the critical section
			n := curInside.Add(1)
			if n > maxInside.Load() {
				maxInside.Store(n)
			}

			// Simulate work (PID check + spawn)
			time.Sleep(5 * time.Millisecond)

			curInside.Add(-1)
			// Lock released by f.Close() in defer
		}()
	}

	wg.Wait()

	if lockErrors.Load() != 0 {
		t.Errorf("lock errors: %d", lockErrors.Load())
	}
	if max := maxInside.Load(); max != 1 {
		t.Errorf("max concurrent in critical section = %d, want 1", max)
	}
}

func TestStopRunning_RunningProcess(t *testing.T) {
	dir := t.TempDir()
	paths := config.Paths{ConfigDir: dir}
	pidFile := PIDFilePath(paths)

	// Start a real background process that we can signal
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start sleep process: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() {
		cmd.Process.Kill()   //nolint:errcheck
		cmd.Process.Wait()   //nolint:errcheck
	})

	// Write its PID to the PID file
	os.WriteFile(pidFile, []byte(strconv.Itoa(pid)), pidFilePerms)

	// StopRunning should send SIGTERM and the process should exit
	if err := StopRunning(paths); err != nil {
		t.Errorf("StopRunning with running process should not error: %v", err)
	}

	// Reap the zombie so IsProcessRunning returns false
	cmd.Wait() //nolint:errcheck

	// PID file should be cleaned up
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Error("PID file should be removed after stopping")
	}

	// Process should no longer be running
	if IsProcessRunning(pid) {
		t.Error("process should not be running after StopRunning")
	}
}

func TestSignalReloadPairing_NonexistentPID(t *testing.T) {
	// Should not panic when sending to a PID that doesn't exist
	signalReloadPairing(999999999)
}

func TestSignalReloadPairing_DeliversSIGUSR2(t *testing.T) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	defer signal.Stop(ch)

	signalReloadPairing(os.Getpid())

	select {
	case sig := <-ch:
		if sig != syscall.SIGUSR2 {
			t.Errorf("received %v, want SIGUSR2", sig)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SIGUSR2")
	}
}

func TestEnsureRunning_AlreadyRunning(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	os.MkdirAll(keysDir, 0700)
	paths := config.Paths{
		ConfigDir: dir,
		KeysDir:   keysDir,
	}

	store := auth.NewMemorySecretStore()

	// Generate an identity so HasIdentity returns true
	if _, err := auth.GenerateIdentity(keysDir, store); err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}

	// Write our own PID to simulate a running agent
	pidFile := PIDFilePath(paths)
	os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), pidFilePerms)
	t.Cleanup(func() { os.Remove(pidFile) })

	// Register to catch SIGUSR1 (EnsureRunning signals activity)
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	defer signal.Stop(ch)

	// EnsureRunning should detect the running process and signal it
	err := EnsureRunning(paths, store, nil)
	if err != nil {
		t.Errorf("EnsureRunning with running agent should not error: %v", err)
	}

	// Should have received SIGUSR1
	select {
	case sig := <-ch:
		if sig != syscall.SIGUSR1 {
			t.Errorf("received %v, want SIGUSR1", sig)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SIGUSR1 from EnsureRunning")
	}
}
