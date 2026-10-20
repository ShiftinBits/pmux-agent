//go:build stress

// Package stress contains stress tests for the pmux agent.
// These tests verify stability under load and are separated from regular tests
// because they require tmux and may take several minutes.
// Run with: go test -tags=stress -race -timeout=300s ./test/stress/... -v
package stress

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

const connectSocket = "pmux-stress-connect"

// TestConnectDisconnect_50Cycles performs 50 rapid connect/disconnect cycles
// and verifies that goroutine count returns to baseline with no leaks.
func TestConnectDisconnect_50Cycles(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, connectSocket)

	tc := tmux.NewClient(connectSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, newTestLogger(), "test", "")

	// Create an anchor session so the tmux server stays alive throughout
	_, err := tc.CreateSession("stress-anchor", "")
	if err != nil {
		t.Fatalf("CreateSession (anchor): %v", err)
	}

	// Get the pane ID for attachment
	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Allow runtime to stabilize before baseline measurement
	runtime.GC()
	time.Sleep(500 * time.Millisecond)
	baseline := runtime.NumGoroutine()
	t.Logf("baseline goroutines: %d", baseline)

	var memBefore runtime.MemStats
	runtime.ReadMemStats(&memBefore)

	const cycles = 50
	start := time.Now()

	for i := 0; i < cycles; i++ {
		peerID := fmt.Sprintf("cycle-peer-%d", i)
		catcher.reset()

		// Attach
		h.HandleMessage(peerID, &protocol.AttachRequest{
			Type:   "attach",
			PaneID: paneID,
			Cols:   80,
			Rows:   24,
		})
		catcher.waitForPeer(t, peerID, "attached", 5*time.Second)

		// Send a small input
		marker := fmt.Sprintf("CYCLE_%d", i)
		h.HandleMessage(peerID, &protocol.InputRequest{
			Type: "input",
			Data: []byte("echo " + marker + "\n"),
		})

		// Brief pause to let output start flowing
		time.Sleep(50 * time.Millisecond)

		// Detach
		catcher.reset()
		h.HandleMessage(peerID, &protocol.DetachRequest{Type: "detach"})
		catcher.waitForPeer(t, peerID, "detached", 5*time.Second)

		// Disconnect
		h.PeerDisconnected(peerID)
	}

	elapsed := time.Since(start)
	t.Logf("completed %d connect/disconnect cycles in %v (avg %v/cycle)", cycles, elapsed, elapsed/cycles)

	// Measure memory after all cycles
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)
	allocatedMB := float64(memAfter.TotalAlloc-memBefore.TotalAlloc) / (1024 * 1024)
	t.Logf("memory allocated during cycles: %.2f MB", allocatedMB)
	t.Logf("heap in use: before=%.2f MB, after=%.2f MB",
		float64(memBefore.HeapInuse)/(1024*1024),
		float64(memAfter.HeapInuse)/(1024*1024))

	// Wait for goroutines to drain. Give them plenty of time since
	// PTY relay goroutines need to notice their FIFOs are closed.
	var final int
	for attempt := 0; attempt < 30; attempt++ {
		runtime.GC()
		time.Sleep(200 * time.Millisecond)
		final = runtime.NumGoroutine()
		if final <= baseline+5 {
			break
		}
	}

	t.Logf("final goroutines: %d (baseline was %d, delta: %d)", final, baseline, final-baseline)
	if final > baseline+5 {
		t.Errorf("goroutine leak: baseline=%d, final=%d, delta=%d (max allowed delta: +5)", baseline, final, final-baseline)
	}
}

// --- Shared test helpers ---

func skipIfNoTmux(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("tmux"); err != nil {
		t.Skip("tmux not available, skipping")
	}
}

func cleanupTmuxServer(t *testing.T, socket string) {
	t.Helper()
	exec.Command("tmux", "-L", socket, "kill-server").Run() //nolint:errcheck
	t.Cleanup(func() {
		exec.Command("tmux", "-L", socket, "kill-server").Run() //nolint:errcheck
	})
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// messageCatcher captures sent protocol messages for test assertions.
type messageCatcher struct {
	mu       sync.Mutex
	messages []capturedMsg
}

type capturedMsg struct {
	PeerID string
	Msg    protocol.Message
}

func (mc *messageCatcher) Send(peerID string, msg protocol.Message) error {
	mc.mu.Lock()
	mc.messages = append(mc.messages, capturedMsg{PeerID: peerID, Msg: msg})
	mc.mu.Unlock()
	return nil
}

func (mc *messageCatcher) get() []capturedMsg {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	cp := make([]capturedMsg, len(mc.messages))
	copy(cp, mc.messages)
	return cp
}

func (mc *messageCatcher) waitFor(t *testing.T, msgType string, timeout time.Duration) protocol.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs := mc.get()
		for _, m := range msgs {
			if m.Msg.MessageType() == msgType {
				return m.Msg
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for message type %q", msgType)
	return nil
}

func (mc *messageCatcher) waitForPeer(t *testing.T, peerID, msgType string, timeout time.Duration) protocol.Message {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs := mc.get()
		for _, m := range msgs {
			if m.PeerID == peerID && m.Msg.MessageType() == msgType {
				return m.Msg
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for message type %q from peer %q", msgType, peerID)
	return nil
}

func (mc *messageCatcher) reset() {
	mc.mu.Lock()
	mc.messages = nil
	mc.mu.Unlock()
}

func (mc *messageCatcher) countType(peerID, msgType string) int {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	count := 0
	for _, m := range mc.messages {
		if m.PeerID == peerID && m.Msg.MessageType() == msgType {
			count++
		}
	}
	return count
}

func (mc *messageCatcher) getAllForPeer(peerID, msgType string) []protocol.Message {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	var result []protocol.Message
	for _, m := range mc.messages {
		if m.PeerID == peerID && m.Msg.MessageType() == msgType {
			result = append(result, m.Msg)
		}
	}
	return result
}
