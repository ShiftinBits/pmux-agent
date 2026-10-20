//go:build stress

package stress

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

const outputSocket = "pmux-stress-output"

// TestLargeOutput_10MB pushes approximately 10MB of data through a terminal pane
// and measures throughput. Uses dd + base64 to generate predictable large output.
func TestLargeOutput_10MB(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, outputSocket)

	tc := tmux.NewClient(outputSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, newTestLogger(), "test", "")

	// Create a session for the test
	_, err := tc.CreateSession("large-output", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	// Attach a peer
	h.HandleMessage("output-peer", &protocol.AttachRequest{
		Type:   "attach",
		PaneID: paneID,
		Cols:   200,
		Rows:   50,
	})
	catcher.waitForPeer(t, "output-peer", "attached", 5*time.Second)

	// Let initial output settle
	time.Sleep(500 * time.Millisecond)
	catcher.reset()

	// Send the dd+base64 command that generates ~10MB of output.
	// dd generates 10240 * 1024 = 10MB of random bytes.
	// base64 encoding expands that by ~33%, producing ~13.3MB of text output.
	//
	// After the data command completes, send a separate echo command with
	// a unique end marker. This avoids detecting the marker in the terminal's
	// command echo (which echoes the typed command before it executes).
	endMarker := fmt.Sprintf("DONE_%d_DONE", time.Now().UnixNano())
	dataCmd := "dd if=/dev/urandom bs=1024 count=10240 2>/dev/null | base64\n"

	start := time.Now()
	h.HandleMessage("output-peer", &protocol.InputRequest{
		Type: "input",
		Data: []byte(dataCmd),
	})

	// Send the marker command after a brief delay so it's a separate command
	// that executes after dd+base64 completes. The shell queues it.
	time.Sleep(100 * time.Millisecond)
	h.HandleMessage("output-peer", &protocol.InputRequest{
		Type: "input",
		Data: []byte(fmt.Sprintf("echo %s\n", endMarker)),
	})

	// Collect output until we see the end marker echoed as command output
	// (not as part of the command line). We detect this by requiring a
	// substantial amount of data before the marker (the base64 output comes first).
	const timeout = 60 * time.Second
	deadline := time.Now().Add(timeout)
	totalBytes := 0
	markerFound := false
	lastIdx := 0

	for time.Now().Before(deadline) {
		msgs := catcher.get()
		// Only process new messages since last check
		for i := lastIdx; i < len(msgs); i++ {
			m := msgs[i]
			if m.PeerID == "output-peer" {
				if out, ok := m.Msg.(*protocol.OutputEvent); ok {
					totalBytes += len(out.Data)
					// Only consider the marker valid if we've already received
					// a substantial amount of data (the base64 output)
					if totalBytes > 1024*1024 && strings.Contains(string(out.Data), endMarker) {
						markerFound = true
					}
				}
			}
		}
		lastIdx = len(msgs)

		if markerFound {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	elapsed := time.Since(start)

	// Log performance metrics
	totalMB := float64(totalBytes) / (1024 * 1024)
	throughput := totalMB / elapsed.Seconds()
	t.Logf("total bytes received: %d (%.2f MB)", totalBytes, totalMB)
	t.Logf("elapsed time: %v", elapsed)
	t.Logf("throughput: %.2f MB/s", throughput)

	if !markerFound {
		t.Errorf("end marker not found within %v timeout; received %.2f MB so far", timeout, totalMB)
	}

	// Verify we received a substantial amount of data.
	// The base64 output of 10MB random data should be ~13.3MB, but tmux pipe-pane
	// may buffer/truncate some output. We check for at least 10MB received.
	const minExpectedMB = 10.0
	if totalMB < minExpectedMB {
		t.Errorf("insufficient output: got %.2f MB, expected at least %.0f MB", totalMB, minExpectedMB)
	}

	// Cleanup
	h.HandleMessage("output-peer", &protocol.DetachRequest{Type: "detach"})
	h.PeerDisconnected("output-peer")
}
