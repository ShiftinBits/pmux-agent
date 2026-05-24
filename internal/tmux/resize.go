package tmux

import (
	"fmt"
	"sync"
)

// PaneSizeTracker records which pane windows the agent has forced to a mobile's
// dimensions, so that when the mobile detaches the manual window-size override
// can be released and tmux resumes fitting the window to whatever terminal
// client is attached — including tracking that client's live resizes.
//
// Pocketmux is single-pairing (one mobile per host), so there is no attach
// counting: a pane's window is either currently driven by the mobile or it is
// not. The tracker also does not remember the pre-mobile dimensions — on
// detach it hands sizing back to tmux rather than restoring a stale snapshot.
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
// alone in its window this resizes the window, which makes tmux set the
// window's window-size option to "manual" while a terminal client is attached;
// RestoreIfLast releases that override on detach.
//
// The pane is only marked on success so that RestoreIfLast never tries to
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

// RestoreIfLast releases the manual window-size override on the pane's window so
// tmux auto-fits it to the attached terminal client again and resumes tracking
// that client's live resizes. Under the single-pairing model the detaching
// mobile is always the last (and only) one, so this runs on every detach.
//
// It is a no-op for panes that were never forced, and tolerates a pane or
// window that has since been killed.
func (t *PaneSizeTracker) RestoreIfLast(paneID string) error {
	t.mu.Lock()
	forced := t.forced[paneID]
	delete(t.forced, paneID)
	t.mu.Unlock()

	if !forced {
		return nil
	}

	wt, err := t.client.WindowForPane(paneID)
	if err != nil {
		return nil //nolint:nilerr // pane/window may have been killed; nothing to release
	}
	return t.client.ClearWindowSizeOverride(wt)
}
