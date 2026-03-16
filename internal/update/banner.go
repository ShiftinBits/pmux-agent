package update

import (
	"fmt"
	"os"
)

// PrintBannerIfAvailable reads the state file and prints a one-line
// update notice to stderr if an update is available.
// Errors are silently ignored — the banner is best-effort.
func PrintBannerIfAvailable(stateFile string) {
	state, err := LoadState(stateFile)
	if err != nil || !state.UpdateAvailable {
		return
	}

	fmt.Fprintf(os.Stderr, "A new version of pmux is available: %s → %s. Run 'pmux update' to update.\n",
		state.CurrentVersion, state.LatestVersion)
}
