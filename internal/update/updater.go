package update

import (
	"fmt"
	"log/slog"
)

// Updater applies an update using an install-method-specific strategy.
type Updater interface {
	// Update applies the update for the given release.
	// For methods requiring elevated privileges, it downloads the package
	// and prints the command the user should run.
	Update(release ReleaseInfo) error

	// Description returns a human-readable description of the update method.
	Description() string
}

// NewUpdater returns the appropriate Updater for the given install method.
func NewUpdater(method InstallMethod, currentVersion string, logger *slog.Logger) Updater {
	switch method {
	case MethodHomebrew:
		return &homebrewUpdater{logger: logger}
	case MethodSnap:
		return &snapUpdater{logger: logger}
	case MethodDeb:
		return &debUpdater{logger: logger}
	case MethodRPM:
		return &rpmUpdater{logger: logger}
	case MethodGitHub:
		return &githubUpdater{current: currentVersion, logger: logger}
	case MethodDev:
		return &devUpdater{}
	default:
		return &devUpdater{}
	}
}

// ErrElevationRequired indicates the update needs elevated privileges.
type ErrElevationRequired struct {
	Command string
}

func (e *ErrElevationRequired) Error() string {
	return fmt.Sprintf("elevated privileges required, run: %s", e.Command)
}
