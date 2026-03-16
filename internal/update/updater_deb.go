package update

import (
	"fmt"
	"log/slog"
	"runtime"
	"strings"
)

type debUpdater struct {
	logger *slog.Logger
}

func (u *debUpdater) Description() string {
	return "Debian package (dpkg -i)"
}

func (u *debUpdater) Update(release ReleaseInfo) error {
	asset, err := findAsset(release, ".deb", runtime.GOARCH)
	if err != nil {
		return err
	}

	fmt.Printf("Download the updated package and install it:\n\n")
	fmt.Printf("  curl -LO %s\n", asset.BrowserDownloadURL)
	fmt.Printf("  sudo dpkg -i %s\n\n", asset.Name)
	return nil
}

// findAsset locates a release asset matching the given suffix and architecture.
func findAsset(release ReleaseInfo, suffix, arch string) (ReleaseAsset, error) {
	for _, a := range release.Assets {
		if strings.HasSuffix(a.Name, suffix) && strings.Contains(a.Name, arch) {
			return a, nil
		}
	}
	return ReleaseAsset{}, fmt.Errorf("no %s asset found for %s in release %s", suffix, arch, release.TagName)
}
