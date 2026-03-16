package update

import (
	"fmt"
	"log/slog"
	"runtime"
)

type rpmUpdater struct {
	logger *slog.Logger
}

func (u *rpmUpdater) Description() string {
	return "RPM package (rpm -U)"
}

func (u *rpmUpdater) Update(release ReleaseInfo) error {
	asset, err := findAsset(release, ".rpm", runtime.GOARCH)
	if err != nil {
		return err
	}

	fmt.Printf("Download the updated package and install it:\n\n")
	fmt.Printf("  curl -LO %s\n", asset.BrowserDownloadURL)
	fmt.Printf("  sudo rpm -U %s\n\n", asset.Name)
	return nil
}
