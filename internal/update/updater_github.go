package update

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/minio/selfupdate"
)

type githubUpdater struct {
	current string
	logger  *slog.Logger
}

func (u *githubUpdater) Description() string {
	return "GitHub Releases (self-update)"
}

func (u *githubUpdater) Update(release ReleaseInfo) error {
	// Find the right archive for this OS/arch.
	archiveName, err := u.matchArchiveName(release)
	if err != nil {
		return err
	}

	var archiveAsset, checksumsAsset ReleaseAsset
	for _, a := range release.Assets {
		if a.Name == archiveName {
			archiveAsset = a
		}
		if a.Name == "checksums.txt" {
			checksumsAsset = a
		}
	}
	if archiveAsset.BrowserDownloadURL == "" {
		return fmt.Errorf("archive asset %q not found in release", archiveName)
	}
	if checksumsAsset.BrowserDownloadURL == "" {
		return fmt.Errorf("checksums.txt not found in release")
	}

	u.logger.Info("downloading update", "archive", archiveName)
	fmt.Printf("Downloading %s...\n", archiveName)

	// Download checksums first (1 MB limit — checksums.txt is a few KB).
	expectedHash, err := u.fetchExpectedChecksum(checksumsAsset.BrowserDownloadURL, archiveName)
	if err != nil {
		return fmt.Errorf("fetch checksums: %w", err)
	}

	// Download archive (100 MB limit — binary is typically 15-30 MB).
	archiveData, err := u.download(archiveAsset.BrowserDownloadURL, 100<<20)
	if err != nil {
		return fmt.Errorf("download archive: %w", err)
	}

	// Verify checksum.
	actualHash := sha256.Sum256(archiveData)
	actualHex := hex.EncodeToString(actualHash[:])
	if actualHex != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHex)
	}
	u.logger.Info("checksum verified", "sha256", actualHex)

	// Extract the pmux binary from the archive.
	binaryData, err := u.extractBinary(archiveData, archiveName)
	if err != nil {
		return fmt.Errorf("extract binary: %w", err)
	}

	// Apply the update using selfupdate.
	fmt.Println("Applying update...")
	if err := selfupdate.Apply(bytes.NewReader(binaryData), selfupdate.Options{}); err != nil {
		if rerr := selfupdate.RollbackError(err); rerr != nil {
			return fmt.Errorf("update failed and rollback also failed: %w", rerr)
		}
		return fmt.Errorf("update failed (rolled back): %w", err)
	}

	return nil
}

// matchArchiveName returns the expected release archive filename for this OS/arch.
func (u *githubUpdater) matchArchiveName(release ReleaseInfo) (string, error) {
	version := strings.TrimPrefix(release.TagName, "v")
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	// macOS universal binary uses "darwin_all".
	archSuffix := goarch
	if goos == "darwin" {
		archSuffix = "all"
	}

	var ext string
	switch goos {
	case "darwin":
		ext = ".zip"
	default:
		ext = ".tar.gz"
	}

	name := fmt.Sprintf("pmux_%s_%s_%s%s", version, goos, archSuffix, ext)

	// Verify the asset actually exists.
	for _, a := range release.Assets {
		if a.Name == name {
			return name, nil
		}
	}

	return "", fmt.Errorf("no release asset matching %q found for %s/%s", name, goos, goarch)
}

// fetchExpectedChecksum downloads checksums.txt and extracts the SHA256 for the given filename.
func (u *githubUpdater) fetchExpectedChecksum(url, filename string) (string, error) {
	data, err := u.download(url, 1<<20) // 1 MB limit for checksums.txt
	if err != nil {
		return "", err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		// Format: "<hash>  <filename>"
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == filename {
			return parts[0], nil
		}
	}

	return "", fmt.Errorf("no checksum found for %s in checksums.txt", filename)
}

var allowedDownloadHosts = map[string]bool{
	"github.com":                    true,
	"objects.githubusercontent.com": true,
}

// download fetches a URL and returns the response body, limited to maxBytes.
func (u *githubUpdater) download(url string, maxBytes int64) ([]byte, error) {
	parsed, err := neturl.Parse(url)
	if err != nil || !allowedDownloadHosts[parsed.Host] {
		return nil, fmt.Errorf("untrusted download URL host: %s", url)
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("untrusted download URL scheme (must be https): %s", url)
	}

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// extractBinary extracts the pmux binary from a tar.gz or zip archive.
func (u *githubUpdater) extractBinary(archiveData []byte, archiveName string) ([]byte, error) {
	if strings.HasSuffix(archiveName, ".zip") {
		return u.extractFromZip(archiveData)
	}
	return u.extractFromTarGz(archiveData)
}

func (u *githubUpdater) extractFromTarGz(data []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("open gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if filepath.Base(hdr.Name) == "pmux" && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 100<<20))
		}
	}
	return nil, fmt.Errorf("pmux binary not found in archive")
}

func (u *githubUpdater) extractFromZip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}

	for _, f := range zr.File {
		if filepath.Base(f.Name) == "pmux" && !f.FileInfo().IsDir() {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, 100<<20))
		}
	}
	return nil, fmt.Errorf("pmux binary not found in zip archive")
}
