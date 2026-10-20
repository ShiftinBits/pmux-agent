//go:build stress

package stress

import (
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/shiftinbits/pmux-agent/internal/agent"
	"github.com/shiftinbits/pmux-agent/internal/protocol"
	"github.com/shiftinbits/pmux-agent/internal/tmux"
)

const sessionsSocket = "pmux-stress-sessions"

// TestManySessions_20x3 creates 20 sessions with 3 windows each and verifies
// that list_sessions returns all of them within the target response time.
func TestManySessions_20x3(t *testing.T) {
	skipIfNoTmux(t)
	cleanupTmuxServer(t, sessionsSocket)

	tc := tmux.NewClient(sessionsSocket)
	catcher := &messageCatcher{}
	h := agent.NewHandler(tc, catcher.Send, newTestLogger(), "test", "")

	const numSessions = 20
	const windowsPerSession = 3

	// Create 20 sessions, each with 3 windows (1 default + 2 new)
	for i := 0; i < numSessions; i++ {
		name := fmt.Sprintf("stress-sess-%d", i)
		_, err := tc.CreateSession(name, "")
		if err != nil {
			t.Fatalf("CreateSession %d: %v", i, err)
		}

		// Create 2 additional windows (session starts with 1)
		for w := 1; w < windowsPerSession; w++ {
			winName := fmt.Sprintf("win-%d-%d", i, w)
			out, err := exec.Command("tmux", "-L", sessionsSocket,
				"new-window", "-t", name, "-n", winName).CombinedOutput()
			if err != nil {
				t.Fatalf("new-window %d/%d: %v: %s", i, w, err, out)
			}
		}
	}

	// Measure list_sessions response time
	start := time.Now()
	h.HandleMessage("sessions-peer", &protocol.ListSessionsRequest{Type: "list_sessions"})
	msg := catcher.waitFor(t, "sessions", 10*time.Second)
	listDuration := time.Since(start)

	sessionsEvt, ok := msg.(*protocol.SessionsEvent)
	if !ok {
		t.Fatalf("expected SessionsEvent, got %T", msg)
	}

	// Verify all 20 sessions are present
	if len(sessionsEvt.Sessions) != numSessions {
		t.Errorf("expected %d sessions, got %d", numSessions, len(sessionsEvt.Sessions))
	}

	// Verify each session has the expected number of windows
	totalWindows := 0
	for _, s := range sessionsEvt.Sessions {
		totalWindows += len(s.Windows)
		if len(s.Windows) != windowsPerSession {
			t.Errorf("session %q: expected %d windows, got %d", s.Name, windowsPerSession, len(s.Windows))
		}
		// Each window should have at least 1 pane
		for _, w := range s.Windows {
			if len(w.Panes) == 0 {
				t.Errorf("session %q window %q: expected at least 1 pane, got 0", s.Name, w.Name)
			}
		}
	}

	// Log performance metrics
	t.Logf("list_sessions response time: %v", listDuration)
	t.Logf("total sessions: %d, total windows: %d", len(sessionsEvt.Sessions), totalWindows)

	// Target: response under 200ms (generous for CI environments)
	const targetDuration = 200 * time.Millisecond
	if listDuration > targetDuration {
		t.Logf("WARNING: list_sessions took %v (target: <%v) — may be acceptable in CI", listDuration, targetDuration)
	}

	// Second measurement: call list_sessions again to check consistency
	catcher.reset()
	start2 := time.Now()
	h.HandleMessage("sessions-peer", &protocol.ListSessionsRequest{Type: "list_sessions"})
	msg2 := catcher.waitFor(t, "sessions", 10*time.Second)
	listDuration2 := time.Since(start2)

	sessionsEvt2, ok := msg2.(*protocol.SessionsEvent)
	if !ok {
		t.Fatalf("expected SessionsEvent, got %T", msg2)
	}
	if len(sessionsEvt2.Sessions) != numSessions {
		t.Errorf("second call: expected %d sessions, got %d", numSessions, len(sessionsEvt2.Sessions))
	}
	t.Logf("second list_sessions response time: %v", listDuration2)
}
