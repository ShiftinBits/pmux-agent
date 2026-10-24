package update

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type homebrewUpdater struct {
	logger *slog.Logger
}

func (u *homebrewUpdater) Description() string {
	return "Homebrew (brew upgrade)"
}

func (u *homebrewUpdater) Update(_ ReleaseInfo) error {
	brewPath, err := exec.LookPath("brew")
	if err != nil {
		return fmt.Errorf("brew not found in PATH: %w", err)
	}

	u.logger.Info("running brew upgrade", "brew", brewPath)
	fmt.Println("Updating via Homebrew...")

	cmd := exec.Command(brewPath, brewUpgradeArgs()...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("brew upgrade failed: %w", err)
	}
	return nil
}

// brewUpgradeArgs returns the brew arguments for upgrading pmux. A binary
// living under a Caskroom was installed from the tap's cask, so --cask keeps
// brew from resolving the token to a same-named formula.
func brewUpgradeArgs() []string {
	args := []string{"upgrade"}
	if exePath, err := executablePath(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			exePath = resolved
		}
		if strings.Contains(exePath, "/Caskroom/") {
			args = append(args, "--cask")
		}
	}
	return append(args, "shiftinbits/tap/pmux")
}
