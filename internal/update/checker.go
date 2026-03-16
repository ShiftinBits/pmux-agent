package update

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

const (
	// defaultRepo is the GitHub repository for pmux-agent releases.
	defaultRepo = "ShiftinBits/pmux-agent"

	// httpTimeout is the deadline for GitHub API requests.
	httpTimeout = 10 * time.Second
)

// ReleaseInfo holds data from the GitHub Releases API response.
type ReleaseInfo struct {
	TagName string         `json:"tag_name"`
	HTMLURL string         `json:"html_url"`
	Assets  []ReleaseAsset `json:"assets"`
}

// ReleaseAsset represents a downloadable file attached to a release.
type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// Checker queries GitHub Releases and updates the state file.
type Checker struct {
	repo       string
	current    string
	stateFile  string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewChecker creates an update checker for the given version and state file path.
func NewChecker(currentVersion, stateFile string, logger *slog.Logger) *Checker {
	return &Checker{
		repo:      defaultRepo,
		current:   currentVersion,
		stateFile: stateFile,
		httpClient: &http.Client{
			Timeout: httpTimeout,
		},
		logger: logger,
	}
}

// Check queries GitHub for the latest release, compares versions,
// and writes the result to the state file.
// Returns the updated state and any error encountered.
func (c *Checker) Check(method InstallMethod) (State, error) {
	if c.current == "dev" {
		return State{CurrentVersion: "dev"}, nil
	}

	release, err := c.FetchRelease()
	if err != nil {
		return State{}, fmt.Errorf("fetch latest release: %w", err)
	}

	latest := release.TagName
	updateAvailable := CompareVersions(c.current, latest) < 0

	binaryPath, _ := os.Executable()

	state := State{
		LastCheck:       time.Now().UTC(),
		CurrentVersion:  c.current,
		LatestVersion:   latest,
		UpdateAvailable: updateAvailable,
		ReleaseURL:      release.HTMLURL,
		InstallMethod:   string(method),
		BinaryPath:      binaryPath,
	}

	if err := SaveState(c.stateFile, state); err != nil {
		c.logger.Warn("failed to save update state", "error", err)
		// Return the state anyway — the check succeeded even if persistence didn't.
	}

	return state, nil
}

// FetchRelease fetches the latest release info from GitHub.
func (c *Checker) FetchRelease() (ReleaseInfo, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", c.repo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ReleaseInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", fmt.Sprintf("pmux/%s", c.current))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("GitHub API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return ReleaseInfo{}, fmt.Errorf("GitHub API rate limited (HTTP %d)", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return ReleaseInfo{}, fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return ReleaseInfo{}, fmt.Errorf("read response body: %w", err)
	}

	var release ReleaseInfo
	if err := json.Unmarshal(body, &release); err != nil {
		return ReleaseInfo{}, fmt.Errorf("parse release JSON: %w", err)
	}

	return release, nil
}
