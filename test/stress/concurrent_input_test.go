//go:build stress

package stress

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

const concurrentSocket = "pmux-stress-concurrent"

// TestConcurrentInput_TwoPeers attaches two peers to different panes and
// has both send input simultaneously for 2 seconds. Verifies that no
// cross-talk occurs (peer A's output does not appear in peer B's stream).
func TestConcurrentInput_TwoPeers(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, concurrentSocket)

	tc := tmux.NewClient(concurrentSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, newTestLogger(), "test", "")

	// Create two separate sessions for isolation
	_, err := tc.CreateSession("concurrent-1", "")
	if err != nil {
		t.Fatalf("CreateSession 1: %v", err)
	}
	_, err = tc.CreateSession("concurrent-2", "")
	if err != nil {
		t.Fatalf("CreateSession 2: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(sessions) < 2 {
		t.Fatalf("expected at least 2 sessions, got %d", len(sessions))
	}

	pane1 := sessions[0].Windows[0].Panes[0].ID
	pane2 := sessions[1].Windows[0].Panes[0].ID

	// Attach both peers
	h.HandleMessage("peerA", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: pane1,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitForPeer(t, "peerA", "attached", 5*time.Second)

	h.HandleMessage("peerB", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: pane2,
		Cols:   80,
		Rows:   24,
	})
	catcher.waitForPeer(t, "peerB", "attached", 5*time.Second)

	// Let initial output settle
	time.Sleep(500 * time.Millisecond)
	catcher.reset()

	// Use unique prefix markers for each peer to detect cross-contamination
	const markerA = "ALPHA_UNIQUE_MARKER"
	const markerB = "BRAVO_UNIQUE_MARKER"

	// Both peers send input simultaneously for 2 seconds.
	// Keep send rate low to avoid PTY buffer pressure under -race.
	const duration = 2 * time.Second
	const sendInterval = 200 * time.Millisecond
	var wg sync.WaitGroup
	done := make(chan struct{})

	go func() {
		time.Sleep(duration)
		close(done)
	}()

	wg.Add(2)

	// Peer A sends unique markers
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-done:
				return
			default:
				h.HandleMessage("peerA", &protocol.InputRequest{
					Type: "input",
					Data: []byte(fmt.Sprintf("echo %s_%d\n", markerA, i)),
				})
				i++
				time.Sleep(sendInterval)
			}
		}
	}()

	// Peer B sends unique markers
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-done:
				return
			default:
				h.HandleMessage("peerB", &protocol.InputRequest{
					Type: "input",
					Data: []byte(fmt.Sprintf("echo %s_%d\n", markerB, i)),
				})
				i++
				time.Sleep(sendInterval)
			}
		}
	}()

	// Wait for sending goroutines with a hard timeout to avoid test hangs
	sendDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(sendDone)
	}()
	select {
	case <-sendDone:
		// OK
	case <-time.After(30 * time.Second):
		t.Fatal("sending goroutines did not complete within 30s")
	}

	// Wait for remaining output to be delivered
	time.Sleep(2 * time.Second)

	// Check for cross-talk: peer A's output should not contain markerB and vice versa
	msgs := catcher.get()
	peerAOutput := &strings.Builder{}
	peerBOutput := &strings.Builder{}
	peerAMsgCount := 0
	peerBMsgCount := 0

	for _, m := range msgs {
		if out, ok := m.Msg.(*protocol.OutputEvent); ok {
			if m.PeerID == "peerA" {
				peerAOutput.Write(out.Data)
				peerAMsgCount++
			}
			if m.PeerID == "peerB" {
				peerBOutput.Write(out.Data)
				peerBMsgCount++
			}
		}
	}

	t.Logf("peerA output messages: %d, total bytes: %d", peerAMsgCount, peerAOutput.Len())
	t.Logf("peerB output messages: %d, total bytes: %d", peerBMsgCount, peerBOutput.Len())

	// Verify each peer received their own markers
	aOut := peerAOutput.String()
	bOut := peerBOutput.String()

	if !strings.Contains(aOut, markerA) {
		t.Error("peerA did not receive any of its own markers")
	}
	if !strings.Contains(bOut, markerB) {
		t.Error("peerB did not receive any of its own markers")
	}

	// Verify NO cross-talk: peer A should not see markerB in its output
	if strings.Contains(aOut, markerB) {
		t.Error("CROSS-TALK DETECTED: peerA received peerB's marker in its output stream")
	}
	// Verify NO cross-talk: peer B should not see markerA in its output
	if strings.Contains(bOut, markerA) {
		t.Error("CROSS-TALK DETECTED: peerB received peerA's marker in its output stream")
	}

	// Count how many of each marker was received to quantify throughput
	aMarkerCount := strings.Count(aOut, markerA)
	bMarkerCount := strings.Count(bOut, markerB)
	t.Logf("peerA received %d instances of its marker", aMarkerCount)
	t.Logf("peerB received %d instances of its marker", bMarkerCount)

	// Cleanup
	h.HandleMessage("peerA", &protocol.DetachRequest{Type: "detach"})
	h.HandleMessage("peerB", &protocol.DetachRequest{Type: "detach"})
	h.PeerDisconnected("peerA")
	h.PeerDisconnected("peerB")
}
