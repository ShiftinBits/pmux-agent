package tmux

import (
	"strings"
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
	forced := tracker.forced[paneID]
	tracker.mu.Unlock()
	if !forced {
		t.Error("expected pane to be marked forced after attach")
	}
}

func TestPaneSizeTracker_ReleaseWhenPaneKilled(t *testing.T) {
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

	if err := tracker.ReleaseIfForced(paneID); err != nil {
		t.Errorf("ReleaseIfForced on killed pane should not error, got: %v", err)
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

	// Releasing a multi-pane window is a no-op: resize-pane never pinned
	// window-size to manual, so there is no override to clear.
	if err := tracker.ReleaseIfForced(pane1ID); err != nil {
		t.Errorf("ReleaseIfForced on multi-pane window should not error: %v", err)
	}
}

func TestPaneSizeTracker_ReleasesManualWindowSize(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	if _, err := tc.CreateSession("ws-release-test", ""); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	sessions, err := tc.ListAll()
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	paneID := sessions[0].Windows[0].Panes[0].ID
	wt, err := tc.WindowForPane(paneID)
	if err != nil {
		t.Fatalf("WindowForPane: %v", err)
	}

	tracker := NewPaneSizeTracker(tc)
	if err := tracker.TrackAndResize(paneID, 40, 12); err != nil {
		t.Fatalf("TrackAndResize: %v", err)
	}

	// Model the manual window-size override tmux applies to a window when a
	// pane is force-resized while a terminal client is attached. The test
	// harness has no attached client, so set it explicitly to recreate the
	// real-world precondition the bug is about.
	if out, err := tc.run("set-window-option", "-t", wt, "window-size", "manual"); err != nil {
		t.Fatalf("set window-size manual: %v: %s", err, out)
	}
	if out, _ := tc.run("show-options", "-w", "-t", wt, "window-size"); !strings.Contains(out, "manual") {
		t.Fatalf("precondition: expected window-size manual, got %q", out)
	}

	// Detaching the (only) mobile must release the manual override so tmux
	// resumes auto-fitting the window to attached clients and responding to
	// their resizes — instead of leaving it pinned at the mobile's size.
	if err := tracker.ReleaseIfForced(paneID); err != nil {
		t.Fatalf("ReleaseIfForced: %v", err)
	}

	out, err := tc.run("show-options", "-w", "-t", wt, "window-size")
	if err != nil {
		t.Fatalf("show-options after release: %v: %s", err, out)
	}
	if strings.Contains(out, "manual") {
		t.Errorf("window-size still manual after detach: %q; expected it released to automatic", out)
	}

	// The pane must be forgotten, and a repeat release is a harmless no-op.
	tracker.mu.Lock()
	stillForced := tracker.forced[paneID]
	tracker.mu.Unlock()
	if stillForced {
		t.Error("expected pane to be forgotten after release")
	}
	if err := tracker.ReleaseIfForced(paneID); err != nil {
		t.Errorf("second ReleaseIfForced should be a no-op, got: %v", err)
	}
}

func TestPaneSizeTracker_TrackAndResizeError(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	tracker := NewPaneSizeTracker(tc)

	// A well-formed but nonexistent pane: validateTarget passes, the tmux
	// resize fails, so TrackAndResize returns an error and must NOT mark the
	// pane as forced (otherwise ReleaseIfForced would later try to release a
	// window that was never driven by the mobile).
	if err := tracker.TrackAndResize("%99999", 40, 12); err == nil {
		t.Fatal("expected error resizing a nonexistent pane")
	}

	tracker.mu.Lock()
	forced := tracker.forced["%99999"]
	tracker.mu.Unlock()
	if forced {
		t.Error("pane should not be marked forced when the resize fails")
	}
}

func TestPaneSizeTracker_ReleaseToleratesMissingWindow(t *testing.T) {
	skipIfNoTmux(t)
	tc := testClient(t)

	tracker := NewPaneSizeTracker(tc)

	// Seed a forced entry for a pane that does not exist, then release it.
	// WindowForPane fails (the pane is gone), and ReleaseIfForced must swallow
	// that and return nil — there is nothing left to release.
	tracker.mu.Lock()
	tracker.forced["%99999"] = true
	tracker.mu.Unlock()

	if err := tracker.ReleaseIfForced("%99999"); err != nil {
		t.Errorf("ReleaseIfForced should tolerate a missing window, got: %v", err)
	}
}
