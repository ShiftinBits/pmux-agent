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

	return &ErrElevationRequired{
		Command: fmt.Sprintf("curl -LO %s && sudo rpm -U %s", asset.BrowserDownloadURL, asset.Name),
	}
}
