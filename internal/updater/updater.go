package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// Updater handles downloading and applying signature database updates.
// It supports both LMD native signatures and ClamAV CVD databases.
type Updater struct {
	cfg        *config.Config
	httpClient *http.Client
	// OnSignaturesUpdated is called after any signature database has been
	// successfully updated. The daemon wires this to trigger engine reload.
	OnSignaturesUpdated func()
}

// NewUpdater creates and initializes a new Updater.
func NewUpdater(cfg *config.Config) *Updater {
	// Configure HTTP client with timeout from config
	timeout, err := time.ParseDuration(cfg.Updater.RemoteURITimeout)
	if err != nil || timeout <= 0 {
		log.Warn("Invalid remote URI timeout in config, using default 30s", "error", err)
		timeout = 30 * time.Second
	}

	hc := &http.Client{
		Timeout: timeout,
	}

	return &Updater{
		cfg:        cfg,
		httpClient: hc,
	}
}

// Update performs all configured signature updates (LMD and/or ClamAV).
func (u *Updater) Update(ctx context.Context) error {
	var updated bool

	// Update LMD native signatures
	if u.cfg.Updater.AutoUpdateSignatures {
		log.Info("Checking for LMD signature updates...")

		didUpdate, err := u.updateLMDSignatures(ctx)
		if err != nil {
			log.Error("LMD signature update failed", "error", err)
		} else if didUpdate {
			updated = true
		}
	}

	// Update ClamAV databases if both update and scanner are enabled
	if u.cfg.Updater.ClamAVUpdateEnabled && u.cfg.Scanner.ClamAVEnabled {
		log.Info("Checking for ClamAV database updates...")

		didUpdate, err := u.updateClamAV(ctx)
		if err != nil {
			log.Error("ClamAV database update failed", "error", err)
		} else if didUpdate {
			updated = true
		}
	}

	// If any databases were updated, trigger the reload callback
	if updated && u.OnSignaturesUpdated != nil {
		log.Info("Signature databases updated, triggering engine reload...")
		u.OnSignaturesUpdated()
	}

	log.Info("Update process completed", "signatures_changed", updated)
	return nil
}

// updateLMDSignatures handles downloading, verifying, and extracting new LMD signatures.
// Returns true if signatures were actually updated.
func (u *Updater) updateLMDSignatures(ctx context.Context) (bool, error) {
	currentVer, err := u.getCurrentLMDVersion()
	if err != nil {
		log.Warn("Could not determine current LMD signature version", "error", err)
		currentVer = "0" // Treat as no version if error
	}

	remoteVer, err := u.getRemoteVersion(ctx, u.cfg.Updater.SignatureVersionURL)
	if err != nil {
		return false, fmt.Errorf("failed to fetch remote signature version from %s: %w", u.cfg.Updater.SignatureVersionURL, err)
	}

	if remoteVer == currentVer {
		log.Info("LMD signatures are already up to date", "version", remoteVer)
		return false, nil
	}

	log.Info("New LMD signature version found", "current", currentVer, "remote", remoteVer)

	// Download signature package to a temp file
	packagePath := filepath.Join(os.TempDir(), filepath.Base(u.cfg.Updater.SignaturePackURL))
	if err := u.downloadFile(ctx, u.cfg.Updater.SignaturePackURL, packagePath); err != nil {
		return false, fmt.Errorf("failed to download signature package from %s: %w", u.cfg.Updater.SignaturePackURL, err)
	}
	defer os.Remove(packagePath)

	// Extract package into the signatures directory
	sigDirPath := u.cfg.App.SignaturesDir

	if err := os.MkdirAll(sigDirPath, 0755); err != nil {
		return false, fmt.Errorf("failed to create signatures directory %s: %w", sigDirPath, err)
	}

	if err := u.extractTarGz(packagePath, sigDirPath); err != nil {
		return false, fmt.Errorf("failed to extract signature package to %s: %w", sigDirPath, err)
	}

	// Write version file so we can skip re-downloads next time
	versionFileName := filepath.Base(u.cfg.Updater.SignatureVersionURL)
	if err := os.WriteFile(filepath.Join(sigDirPath, versionFileName), []byte(remoteVer), 0644); err != nil {
		return false, fmt.Errorf("failed to write signature version file: %w", err)
	}

	log.Info("LMD signatures updated successfully", "version", remoteVer)
	return true, nil
}

// updateClamAV downloads ClamAV CVD databases from the configured mirror.
// It uses HTTP If-Modified-Since to avoid redundant downloads.
// Returns true if any database was actually updated.
func (u *Updater) updateClamAV(ctx context.Context) (bool, error) {
	// Resolve the ClamAV database directory
	clamDBPath := u.cfg.Scanner.ClamAVDBPath

	if clamDBPath == "" {
		clamDBPath = u.cfg.App.ClamAVDir
	}

	if err := os.MkdirAll(clamDBPath, 0755); err != nil {
		return false, fmt.Errorf("failed to create ClamAV database directory %s: %w", clamDBPath, err)
	}

	mirrorURL := strings.TrimRight(u.cfg.Updater.ClamAVMirrorURL, "/")

	databases := u.cfg.Updater.ClamAVDatabases
	if len(databases) == 0 {
		databases = []string{"daily.cvd", "main.cvd", "bytecode.cvd"}
	}

	var anyUpdated bool

	for _, dbName := range databases {
		select {
		case <-ctx.Done():
			return anyUpdated, ctx.Err()

		default:
		}

		downloadURL := mirrorURL + "/" + dbName
		localPath := filepath.Join(clamDBPath, dbName)

		didUpdate, err := u.downloadClamAVDatabase(ctx, downloadURL, localPath)
		if err != nil {
			log.Warn("Failed to update ClamAV database, skipping", "database", dbName, "error", err)
			continue
		}

		if didUpdate {
			anyUpdated = true
			log.Info("ClamAV database updated", "database", dbName)
		} else {
			log.Info("ClamAV database is already up to date", "database", dbName)
		}
	}

	return anyUpdated, nil
}

// downloadClamAVDatabase downloads a single ClamAV database file if it has been
// modified since the local copy. Returns true if the file was downloaded/updated.
func (u *Updater) downloadClamAVDatabase(ctx context.Context, url, localPath string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request for %s: %w", url, err)
	}

	// Use a freshclam-compatible User-Agent so the official ClamAV CDN accepts our download requests
	// The CDN checks this header and rejects clients that don't identify as ClamAV/freshclam.
	clamAVVersion := "1.4.2"

	osName := runtime.GOOS
	if len(osName) > 0 {
		osName = strings.ToUpper(osName[:1]) + osName[1:]
	}

	userAgent := fmt.Sprintf("ClamAV/%s (OS: %s, ARCH: %s, CPU: %s)",
		clamAVVersion,
		osName,
		runtime.GOARCH,
		runtime.GOARCH)

	req.Header.Set("User-Agent", userAgent)

	// Set If-Modified-Since header based on the local file's modification time
	// so the server can return 304 Not Modified if the file hasn't changed.
	if info, statErr := os.Stat(localPath); statErr == nil {
		req.Header.Set("If-Modified-Since", info.ModTime().UTC().Format(http.TimeFormat))
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to perform HTTP request for %s: %w", url, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// File hasn't changed on the server
		return false, nil
	case http.StatusOK:
		// New data available, download it
	default:
		return false, fmt.Errorf("remote server returned status %d for %s", resp.StatusCode, url)
	}

	// Download to a temp file first, then atomically rename to avoid
	// corrupting the database file if the download is interrupted.
	dir := filepath.Dir(localPath)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(localPath)+".tmp.*")
	if err != nil {
		return false, fmt.Errorf("failed to create temp file in %s: %w", dir, err)
	}

	tmpPath := tmpFile.Name()

	// Ensure cleanup on error
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath)
	}()

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return false, fmt.Errorf("failed to download %s: %w", url, err)
	}

	// Sync to disk before rename for durability
	if err := tmpFile.Sync(); err != nil {
		return false, fmt.Errorf("failed to sync temp file %s: %w", tmpPath, err)
	}

	if err := tmpFile.Close(); err != nil {
		return false, fmt.Errorf("failed to close temp file %s: %w", tmpPath, err)
	}

	// Atomically replace the old file
	if err := os.Rename(tmpPath, localPath); err != nil {
		return false, fmt.Errorf("failed to rename temp file to %s: %w", localPath, err)
	}

	log.Info("Downloaded ClamAV database", "url", url, "path", localPath)
	return true, nil
}

// getCurrentLMDVersion reads the local LMD signature version file.
func (u *Updater) getCurrentLMDVersion() (string, error) {
	sigDirPath := u.cfg.App.SignaturesDir

	versionFilePath := filepath.Join(sigDirPath, filepath.Base(u.cfg.Updater.SignatureVersionURL))

	data, err := os.ReadFile(versionFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read local version file %s: %w", versionFilePath, err)
	}

	return strings.TrimSpace(string(data)), nil
}

// getRemoteVersion fetches the remote version string from a URL.
func (u *Updater) getRemoteVersion(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request for remote version %s: %w", url, err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to perform HTTP request for remote version %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("remote server returned status %d for %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body for remote version %s: %w", url, err)
	}

	return strings.TrimSpace(string(data)), nil
}

// downloadFile downloads a file from a URL to a local path.
func (u *Updater) downloadFile(ctx context.Context, url, outputPath string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request for download %s: %w", url, err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to perform HTTP request for download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("remote server returned status %d for %s", resp.StatusCode, url)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to save downloaded file to %s: %w", outputPath, err)
	}

	log.Info("Downloaded file", "url", url, "path", outputPath)
	return nil
}

// extractTarGz extracts a .tar.gz archive to a destination directory.
func (u *Updater) extractTarGz(archivePath, destDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive %s: %w", archivePath, err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader for %s: %w", archivePath, err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}

		if err != nil {
			return fmt.Errorf("failed to read tar header from %s: %w", archivePath, err)
		}

		name := header.Name
		sigDirName := filepath.Base(u.cfg.App.SignaturesDir) + "/"
		if after, ok := strings.CutPrefix(name, sigDirName); ok {
			name = after
		}

		baseName := filepath.Base(name)
		if baseName == "maldet.sigs.ver" {
			name = baseName
		} else if baseName == "md5v2.dat" || baseName == "sha256v2.dat" || baseName == "hex.dat" {
			name = filepath.Join("dat", baseName)
		} else if strings.HasPrefix(baseName, "rfxn.") {
			name = filepath.Join("rfxn", baseName)
		} else {
			continue // Skip other files
		}

		targetPath := filepath.Join(destDir, name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return fmt.Errorf("failed to create directory for %s: %w", targetPath, err)
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to write file content to %s: %w", targetPath, err)
			}

			outFile.Close()

		case tar.TypeSymlink:
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return fmt.Errorf("failed to create symlink %s: %w", targetPath, err)
			}

		case tar.TypeLink:
			if err := os.Link(filepath.Join(destDir, header.Linkname), targetPath); err != nil {
				return fmt.Errorf("failed to create hardlink %s: %w", targetPath, err)
			}

		default:
			log.Warn("Skipping unknown tar entry type", "type", header.Typeflag, "name", header.Name)
		}
	}

	log.Info("Extracted archive", "path", archivePath, "destination", destDir)
	return nil
}
