package update

import (
	"fmt"
	"log/slog"
)

type snapUpdater struct {
	logger *slog.Logger
}

func (u *snapUpdater) Description() string {
	return "Snap Store (snapd auto-updates)"
}

func (u *snapUpdater) Update(_ ReleaseInfo) error {
	fmt.Println("Snap packages are automatically updated by snapd.")
	fmt.Println("To force an immediate update, run:")
	fmt.Println()
	fmt.Println("  sudo snap refresh pmux")
	fmt.Println()
	return nil
}
