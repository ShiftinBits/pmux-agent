package tmux

import (
	"fmt"
	"sync"
)

// PaneSizeTracker records which pane windows the agent has forced to a mobile's
// dimensions, so that when the mobile detaches the manual window-size override
// can be released and tmux resumes fitting the window to whatever terminal
// client is attached — and responding to that client's terminal resizes.
//
// Pocketmux is single-pairing (one mobile per host) and the handler serializes
// attach/detach for that one peer, so the tracker assumes a single writer:
// there is no attach counting, and a pane's window is either currently driven
// by the mobile or it is not. The tracker also does not remember the pre-mobile
// dimensions — on detach it hands sizing back to tmux rather than restoring a
// stale snapshot.
type PaneSizeTracker struct {
	mu     sync.Mutex
	forced map[string]bool // paneID -> window currently forced to mobile dims
	client *Client
}

// NewPaneSizeTracker creates a tracker that uses the given tmux client.
func NewPaneSizeTracker(client *Client) *PaneSizeTracker {
	return &PaneSizeTracker{
		forced: make(map[string]bool),
		client: client,
	}
}

// TrackAndResize resizes the target pane to the given mobile dimensions and
// records that the pane's window is now driven by the mobile. When the pane is
// alone in its window this resizes the window itself, which makes tmux pin the
// window's window-size option to "manual"; ReleaseIfForced clears that override
// on detach.
//
// The pane is only marked on success so that ReleaseIfForced never tries to
// release a window that was never forced.
func (t *PaneSizeTracker) TrackAndResize(paneID string, cols, rows int) error {
	if err := t.client.ResizePane(paneID, cols, rows); err != nil {
		return fmt.Errorf("resize pane to mobile dimensions: %w", err)
	}

	t.mu.Lock()
	t.forced[paneID] = true
	t.mu.Unlock()
	return nil
}

// ReleaseIfForced clears the manual window-size override on the pane's window —
// but only if this tracker previously forced it — so tmux auto-fits the window
// to the attached terminal client again and resumes responding to that client's
// resizes. Under the single-pairing model the detaching mobile is always the
// only one, so this runs on every detach (and as rollback when an attach
// fails).
//
// It is a no-op, and safe to call repeatedly, for panes that were never forced
// or were already released, and it tolerates a pane or window that has since
// been killed.
func (t *PaneSizeTracker) ReleaseIfForced(paneID string) error {
	t.mu.Lock()
	forced := t.forced[paneID]
	delete(t.forced, paneID)
	t.mu.Unlock()

	if !forced {
		return nil
	}

	wt, err := t.client.WindowForPane(paneID)
	if err != nil {
		return nil //nolint:nilerr // pane/window is commonly gone during detach; nothing to release
	}
	return t.client.ClearWindowSizeOverride(wt)
}
