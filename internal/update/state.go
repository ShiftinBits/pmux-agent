// Package update implements version checking and self-update functionality.
package update

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// State holds the persisted update check result.
type State struct {
	LastCheck       time.Time `json:"lastCheck"`
	CurrentVersion  string    `json:"currentVersion"`
	LatestVersion   string    `json:"latestVersion"`
	UpdateAvailable bool      `json:"updateAvailable"`
	ReleaseURL      string    `json:"releaseURL"`
	InstallMethod   string    `json:"installMethod"`
	BinaryPath      string    `json:"binaryPath"` // for cache invalidation
}

// StateFilePath returns the path to the update state file.
func StateFilePath(configDir string) string {
	return filepath.Join(configDir, "update-state.json")
}

// LoadState reads the update state from disk.
// Returns a zero State and nil error if the file does not exist.
func LoadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return State{}, nil
		}
		return State{}, err
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return State{}, err
	}
	return state, nil
}

// SaveState writes the update state to disk atomically.
// Uses temp file + rename to prevent partial reads by concurrent CLI processes.
func SaveState(path string, state State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "update-state-*.json")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}

	return os.Rename(tmpName, path)
}
