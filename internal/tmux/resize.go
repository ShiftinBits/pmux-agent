package tmux

import (
	"fmt"
	"sync"
)

// PaneSizeTracker tracks mobile attach counts per pane and restores
// original pane dimensions when the last mobile client detaches.
type PaneSizeTracker struct {
	mu          sync.Mutex
	attachCount map[string]int    // paneID -> number of mobiles attached
	origSize    map[string][2]int // paneID -> [cols, rows] before first mobile attach
	client      *Client
}

// NewPaneSizeTracker creates a tracker that uses the given tmux client.
func NewPaneSizeTracker(client *Client) *PaneSizeTracker {
	return &PaneSizeTracker{
		attachCount: make(map[string]int),
		origSize:    make(map[string][2]int),
		client:      client,
	}
}

// TrackAndResize resizes the target pane to the given mobile dimensions
// and increments the attach count. On first attach, the original pane
// dimensions are saved for later restoration.
// The count is only incremented on success so that RestoreIfLast never
// operates on a phantom attach.
func (t *PaneSizeTracker) TrackAndResize(paneID string, cols, rows int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Save original dimensions on first attach
	if t.attachCount[paneID] == 0 {
		origCols, origRows, err := t.client.PaneDimensions(paneID)
		if err != nil {
			return fmt.Errorf("save original pane size: %w", err)
		}
		t.origSize[paneID] = [2]int{origCols, origRows}
	}

	if err := t.client.ResizePane(paneID, cols, rows); err != nil {
		return err
	}

	t.attachCount[paneID]++
	return nil
}

// RestoreIfLast decrements the attach count and restores the pane to its
// original dimensions when the last mobile client detaches.
// Returns nil if the pane was already cleaned up or no longer exists.
func (t *PaneSizeTracker) RestoreIfLast(paneID string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	count, ok := t.attachCount[paneID]
	if !ok || count <= 0 {
		return nil
	}

	t.attachCount[paneID]--
	if t.attachCount[paneID] > 0 {
		return nil // Other mobiles still attached
	}

	delete(t.attachCount, paneID)

	orig, hasOrig := t.origSize[paneID]
	delete(t.origSize, paneID)

	if !hasOrig {
		return nil
	}

	// Restore original pane dimensions. If the pane was killed, ignore the error.
	if err := t.client.ResizePane(paneID, orig[0], orig[1]); err != nil {
		return nil //nolint:nilerr // pane may have been killed
	}

	// Release manual window size constraint so the window auto-fits
	// to the largest attached terminal client.
	wt, err := t.client.WindowForPane(paneID)
	if err != nil {
		return nil //nolint:nilerr // pane/window may have been killed
	}
	return t.client.ResizeWindowAuto(wt)
}
