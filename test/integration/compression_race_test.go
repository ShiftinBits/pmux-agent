//go:build integration

package integration

import (
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

const compressionRaceSocket = "pmux-integ-compress-race"

// compressionRaceMarker is printed continuously by the pane. Deflate output
// is Huffman coded, so seeing it as plaintext in an OutputEvent means raw
// bytes were sent on a compressed stream.
const compressionRaceMarker = "PMUX_COMPRESSION_RACE_MARKER"

// orderedRecorder records every message sent to every peer in send order.
type orderedRecorder struct {
	mu   sync.Mutex
	msgs []protocol.Message
}

func (r *orderedRecorder) Send(_ context.Context, _ string, msg protocol.Message) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, msg)
	r.mu.Unlock()
	return nil
}

func (r *orderedRecorder) snapshot() []protocol.Message {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]protocol.Message(nil), r.msgs...)
}

// waitForStreamOutput waits until an OutputEvent has been sent after the most
// recent AttachedEvent, i.e. the current stream is actively sending.
func (r *orderedRecorder) waitForStreamOutput(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		msgs := r.snapshot()
		for i := len(msgs) - 1; i >= 0; i-- {
			if _, ok := msgs[i].(*protocol.AttachedEvent); ok {
				break
			}
			if _, ok := msgs[i].(*protocol.OutputEvent); ok {
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timeout waiting for output on the current stream")
}

// inflate inflates data with a fresh raw-deflate reader. The agent
// sync-flushes and never closes the stream, so a reader that consumed all of
// it ends with io.ErrUnexpectedEOF; that is the clean outcome.
func inflate(data []byte) ([]byte, error) {
	out, err := io.ReadAll(flate.NewReader(bytes.NewReader(data)))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return out, err
	}
	return out, nil
}

// TestCompression_RapidReattachKeepsStreamIntact detaches and re-attaches a
// compressed peer many times while the pane prints continuously. Each
// attached{compression:deflate} starts a new deflate stream, so every
// OutputEvent up to the next attached must belong to that one stream (no raw
// bytes, no output from the previous stream), and nothing may be sent
// between detached and the next attached.
func TestCompression_RapidReattachKeepsStreamIntact(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, compressionRaceSocket)

	tc := tmux.NewClient(compressionRaceSocket)
	rec := &orderedRecorder{}
	h := agent.NewHandler(tc, rec.Send, newTestLogger(), "test", "")

	if _, err := tc.CreateSession("compress-race",
		"sh -c 'while :; do echo "+compressionRaceMarker+"; done'"); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	attach := func(reattach bool) {
		h.HandleMessage("peer1", &protocol.AttachRequest{
			Type:        "attach",
			PaneID:      paneID,
			Cols:        80,
			Rows:        24,
			Reattach:    reattach,
			Compression: "deflate",
		})
	}

	// Each detach/re-attach happens while the current stream is mid-flow.
	const cycles = 40
	attach(false)
	for i := range cycles {
		rec.waitForStreamOutput(t, 5*time.Second)
		switch i % 3 {
		case 0: // explicit detach, then a fresh attach
			h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
			attach(false)
		case 1: // re-attach over a live stream (no detach in between)
			attach(false)
		case 2: // reconnect-style re-attach that sends the initial content
			attach(true)
		}
	}
	rec.waitForStreamOutput(t, 5*time.Second)
	h.HandleMessage("peer1", &protocol.DetachRequest{Type: "detach"})
	h.PeerDisconnected("peer1")

	msgs := rec.snapshot()

	attachedCount, generationsWithOutput := 0, 0
	inGeneration := false
	var stream []byte
	firstChunk := true

	finish := func() {
		if !inGeneration || len(stream) == 0 {
			return
		}
		generationsWithOutput++
		inflated, err := inflate(stream)
		if err != nil {
			t.Errorf("generation %d: stream does not inflate: %v", attachedCount, err)
			return
		}
		if len(inflated) > 0 && !strings.Contains(string(inflated), compressionRaceMarker) {
			t.Errorf("generation %d: inflated output lacks the pane marker: %q",
				attachedCount, truncate(string(inflated), 200))
		}
	}

	for i, m := range msgs {
		switch ev := m.(type) {
		case *protocol.AttachedEvent:
			finish()
			attachedCount++
			if ev.Compression != "deflate" {
				t.Fatalf("attached #%d: compression = %q, want deflate", attachedCount, ev.Compression)
			}
			inGeneration, stream, firstChunk = true, nil, true
		case *protocol.DetachedEvent:
			finish()
			inGeneration, stream = false, nil
		case *protocol.OutputEvent:
			if !inGeneration {
				t.Fatalf("message %d: output sent while detached (stale stream)", i)
			}
			if bytes.Contains(ev.Data, []byte(compressionRaceMarker)) {
				t.Fatalf("message %d: raw output on a compressed stream", i)
			}
			if firstChunk {
				if _, err := inflate(ev.Data); err != nil {
					t.Fatalf("message %d: first output after attached #%d does not inflate with a fresh reader: %v",
						i, attachedCount, err)
				}
				firstChunk = false
			}
			stream = append(stream, ev.Data...)
		case *protocol.ErrorEvent:
			t.Fatalf("message %d: unexpected error %s: %s", i, ev.Code, ev.Message)
		}
	}
	finish()

	if want := cycles + 1; attachedCount != want {
		t.Errorf("attached events = %d, want %d", attachedCount, want)
	}
	if generationsWithOutput != attachedCount {
		t.Errorf("%d of %d attachments carried output, want all", generationsWithOutput, attachedCount)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
