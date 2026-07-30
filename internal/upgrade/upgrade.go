package upgrade

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// Upgrader handles downloading and preparing the latest LMD-NG release binary.
type Upgrader struct {
	cfg        *config.Config
	httpClient *http.Client
}

// releaseResponse is the GitHub API response for /releases/latest.
type releaseResponse struct {
	TagName         string  `json:"tag_name"`
	TargetCommitish string  `json:"target_commitish"`
	Assets          []asset `json:"assets"`
}

// asset represents a single release asset (downloadable file).
type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// NewUpgrader creates a new Upgrader with the given configuration.
func NewUpgrader(cfg *config.Config) *Upgrader {
	return &Upgrader{
		cfg:        cfg,
		httpClient: &http.Client{},
	}
}

// LatestVersion queries the GitHub Releases API and returns the latest tag_name
// and target_commitish (e.g. "v0.2.0", "abc1234def...", nil) or an error.
func (u *Upgrader) LatestVersion(ctx context.Context) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u.cfg.Updater.ReleaseAPIURL, nil)
	if err != nil {
		return "", "", fmt.Errorf("failed to create release API request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to query release API at %s: %w", u.cfg.Updater.ReleaseAPIURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("release API returned status %d", resp.StatusCode)
	}

	var rel releaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return "", "", fmt.Errorf("failed to decode release API response: %w", err)
	}

	if rel.TagName == "" {
		return "", "", fmt.Errorf("release API returned empty tag_name")
	}

	return rel.TagName, rel.TargetCommitish, nil
}

// DownloadRelease downloads the release archive for the specified version and
// platform, extracts the lmd-ng binary, and returns the path to the extracted
// binary along with a cleanup function to remove temporary files.
//
// The goos and goarch parameters are runtime.GOOS and runtime.GOARCH from the
// caller — they specify which platform's binary to download.
func (u *Upgrader) DownloadRelease(ctx context.Context, version, goos, goarch string) (binaryPath string, cleanup func(), err error) {
	tmpDir := filepath.Join(u.cfg.App.BasePath, "tmp")
	if mkdirErr := os.MkdirAll(tmpDir, 0o700); mkdirErr != nil {
		return "", nil, fmt.Errorf("failed to create tmp directory: %w", mkdirErr)
	}

	// Build asset filename using goreleaser naming conventions
	assetName := buildAssetName(version, goos, goarch)
	downloadURL := buildDownloadURL(version, assetName)

	// Download to temp file
	tmpFile, err := os.CreateTemp(tmpDir, "lmd-upgrade-*.zip")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file for download: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}()

	log.Info("Downloading release", "url", downloadURL)

	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create download request: %w", err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to download release from %s: %w", downloadURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("download returned status %d for %s", resp.StatusCode, downloadURL)
	}

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return "", nil, fmt.Errorf("failed to save download to %s: %w", tmpPath, err)
	}
	tmpFile.Close()

	// Extract binary from archive
	extractedPath, extractErr := extractBinary(tmpPath, tmpDir, goos)
	if extractErr != nil {
		return "", nil, fmt.Errorf("failed to extract binary from archive: %w", extractErr)
	}

	cleanup = func() {
		os.Remove(extractedPath)
	}

	return extractedPath, cleanup, nil
}

// buildAssetName constructs the archive filename following goreleaser conventions.
func buildAssetName(version, goos, goarch string) string {
	// Strip leading 'v' from version for filename
	ver := strings.TrimPrefix(version, "v")

	// Map GOOS to goreleaser archive OS name
	archiveOS := goos
	switch goos {
	case "darwin":
		archiveOS = "macos"
	}

	// Map GOARCH to goreleaser archive arch name
	archiveArch := goarch
	switch goarch {
	case "386":
		archiveArch = "32-bit"
	case "amd64":
		archiveArch = "64-bit"
	case "arm64":
		archiveArch = "arm-64-bit"
	}

	return fmt.Sprintf("lmd-ng_%s_%s_%s", ver, archiveOS, archiveArch)
}

// buildDownloadURL constructs the GitHub release download URL.
func buildDownloadURL(version, assetName string) string {
	// version already includes 'v' prefix (from LatestVersion)
	return fmt.Sprintf("https://github.com/dimaskiddo/lmd-ng/releases/download/%s/%s.zip", version, assetName)
}

// extractBinary finds and extracts the lmd-ng binary from a release archive.
func extractBinary(archivePath, destDir, goos string) (string, error) {
	return extractBinaryFromZip(archivePath, destDir)
}

// extractBinaryFromZip extracts the lmd-ng binary from a zip archive.
func extractBinaryFromZip(archivePath, destDir string) (string, error) {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		return "", fmt.Errorf("failed to open zip archive %s: %w", archivePath, err)
	}
	defer r.Close()

	for _, f := range r.File {
		base := filepath.Base(f.Name)
		if base != "lmd-ng" && base != "lmd-ng.exe" {
			continue
		}

		// Extract binary to destDir
		binPath := filepath.Join(destDir, base)

		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("failed to open binary entry in zip: %w", err)
		}

		out, err := os.OpenFile(binPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o755)
		if err != nil {
			rc.Close()
			return "", fmt.Errorf("failed to create binary file %s: %w", binPath, err)
		}

		if _, err := io.Copy(out, rc); err != nil {
			rc.Close()
			out.Close()
			os.Remove(binPath)
			return "", fmt.Errorf("failed to extract binary: %w", err)
		}

		rc.Close()
		out.Close()

		return binPath, nil
	}

	return "", fmt.Errorf("lmd-ng binary not found in archive %s", archivePath)
}
