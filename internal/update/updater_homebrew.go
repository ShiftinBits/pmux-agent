package update

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
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

	cmd := exec.Command(brewPath, "upgrade", "shiftinbits/tap/pmux")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("brew upgrade failed: %w", err)
	}
	return nil
}
