package tmux

import (
	"testing"
	"time"
)

func TestPaneSizeTracker_TrackAndResize(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	_, err := tc.CreateSession("resize-track-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	tracker := NewPaneSizeTracker(tc)

	if err := tracker.TrackAndResize(paneID, 40, 12); err != nil {
		t.Fatalf("TrackAndResize: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	sessions, err = tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	size := sessions[0].Windows[0].Panes[0].Size
	if size.Cols != 40 {
		t.Errorf("cols = %d, want 40", size.Cols)
	}
	if size.Rows != 12 {
		t.Errorf("rows = %d, want 12", size.Rows)
	}

	tracker.mu.Lock()
	count := tracker.attachCount[paneID]
	_, hasOrig := tracker.origSize[paneID]
	tracker.mu.Unlock()
	if count != 1 {
		t.Errorf("attachCount = %d, want 1", count)
	}
	if !hasOrig {
		t.Error("expected origSize to be saved after first attach")
	}
}

func TestPaneSizeTracker_RestoreIfLast(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	_, err := tc.CreateSession("resize-restore-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID
	origCols := sessions[0].Windows[0].Panes[0].Size.Cols
	origRows := sessions[0].Windows[0].Panes[0].Size.Rows

	tracker := NewPaneSizeTracker(tc)

	if err := tracker.TrackAndResize(paneID, 40, 12); err != nil {
		t.Fatalf("TrackAndResize: %v", err)
	}

	if err := tracker.RestoreIfLast(paneID); err != nil {
		t.Fatalf("RestoreIfLast: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	tracker.mu.Lock()
	_, tracked := tracker.attachCount[paneID]
	_, hasOrig := tracker.origSize[paneID]
	tracker.mu.Unlock()
	if tracked {
		t.Error("expected attachCount entry to be removed after last detach")
	}
	if hasOrig {
		t.Error("expected origSize entry to be removed after last detach")
	}

	// Verify dimensions were restored
	sessions, err = tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll after restore: %v", err)
	}
	size := sessions[0].Windows[0].Panes[0].Size
	if size.Cols != origCols {
		t.Errorf("restored cols = %d, want %d", size.Cols, origCols)
	}
	if size.Rows != origRows {
		t.Errorf("restored rows = %d, want %d", size.Rows, origRows)
	}
}

func TestPaneSizeTracker_MultipleAttach_RestoreOnlyAfterLast(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	_, err := tc.CreateSession("multi-attach-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID

	tracker := NewPaneSizeTracker(tc)

	if err := tracker.TrackAndResize(paneID, 40, 12); err != nil {
		t.Fatalf("TrackAndResize 1: %v", err)
	}

	if err := tracker.TrackAndResize(paneID, 50, 15); err != nil {
		t.Fatalf("TrackAndResize 2: %v", err)
	}

	// First detach — should NOT restore (one still attached)
	if err := tracker.RestoreIfLast(paneID); err != nil {
		t.Fatalf("RestoreIfLast 1: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	tracker.mu.Lock()
	count := tracker.attachCount[paneID]
	tracker.mu.Unlock()
	if count != 1 {
		t.Errorf("attachCount after first detach = %d, want 1", count)
	}

	// Verify size is still mobile-resized (50x15 from second attach)
	sessions, err = tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	size := sessions[0].Windows[0].Panes[0].Size
	if size.Cols != 50 || size.Rows != 15 {
		t.Errorf("size after first detach = %dx%d, want 50x15", size.Cols, size.Rows)
	}

	// Second detach — should restore original dimensions
	if err := tracker.RestoreIfLast(paneID); err != nil {
		t.Fatalf("RestoreIfLast 2: %v", err)
	}

	tracker.mu.Lock()
	_, tracked := tracker.attachCount[paneID]
	tracker.mu.Unlock()
	if tracked {
		t.Error("expected attachCount entry to be removed after last detach")
	}
}

func TestPaneSizeTracker_RestoreWhenPaneKilled(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	_, err := tc.CreateSession("killed-pane-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, err = tc.CreateSession("keep-alive", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	var paneID string
	for _, s := range sessions {
		if s.Name == "killed-pane-test" {
			paneID = s.Windows[0].Panes[0].ID
			break
		}
	}
	if paneID == "" {
		t.Fatal("could not find killed-pane-test pane")
	}

	tracker := NewPaneSizeTracker(tc)
	if err := tracker.TrackAndResize(paneID, 40, 12); err != nil {
		t.Fatalf("TrackAndResize: %v", err)
	}

	if err := tc.KillSession("killed-pane-test"); err != nil {
		t.Fatalf("KillSession: %v", err)
	}

	if err := tracker.RestoreIfLast(paneID); err != nil {
		t.Errorf("RestoreIfLast on killed pane should not error, got: %v", err)
	}
}

func TestPaneSizeTracker_MultiPaneSplit(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	_, err := tc.CreateSession("split-test", "")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Get the initial pane
	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	windowTarget := sessions[0].ID + ":" + sessions[0].Windows[0].ID
	pane1ID := sessions[0].Windows[0].Panes[0].ID

	// First resize the window to a known size so the test is deterministic
	if err := tc.ResizeWindow(windowTarget, 100, 30); err != nil {
		t.Fatalf("ResizeWindow: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Split the window horizontally (vertical divider, side-by-side panes)
	out, err := tc.run("split-window", "-h", "-t", pane1ID)
	if err != nil {
		t.Fatalf("split-window: %v: %s", err, out)
	}
	time.Sleep(100 * time.Millisecond)

	// Get both panes and their sizes
	sessions, err = tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll after split: %v", err)
	}
	panes := sessions[0].Windows[0].Panes
	if len(panes) != 2 {
		t.Fatalf("expected 2 panes, got %d", len(panes))
	}

	pane1ID = panes[0].ID
	pane2ID := panes[1].ID
	pane2OrigCols := panes[1].Size.Cols
	pane2OrigRows := panes[1].Size.Rows

	// Resize only pane1 to mobile dimensions
	tracker := NewPaneSizeTracker(tc)
	if err := tracker.TrackAndResize(pane1ID, 30, 15); err != nil {
		t.Fatalf("TrackAndResize: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Verify pane1 columns were resized (rows are shared in a horizontal split
	// so resize-pane -y can't change them independently)
	cols1, _, err := tc.PaneDimensions(pane1ID)
	if err != nil {
		t.Fatalf("PaneDimensions(pane1): %v", err)
	}
	if cols1 != 30 {
		t.Errorf("pane1 cols = %d, want 30", cols1)
	}

	// Verify pane2 was NOT resized to mobile dimensions.
	// With resize-pane, pane2 should gain the columns that pane1 gave up.
	cols2, rows2, err := tc.PaneDimensions(pane2ID)
	if err != nil {
		t.Fatalf("PaneDimensions(pane2): %v", err)
	}
	if cols2 == 30 {
		t.Errorf("pane2 cols should NOT be 30 (mobile dims); got %d", cols2)
	}
	if cols2 < pane2OrigCols {
		t.Errorf("pane2 cols = %d, should be >= original %d (pane1 shrank)", cols2, pane2OrigCols)
	}
	// Rows should be unchanged (horizontal split shares rows)
	if rows2 != pane2OrigRows {
		t.Errorf("pane2 rows = %d, want %d (unchanged)", rows2, pane2OrigRows)
	}
}
