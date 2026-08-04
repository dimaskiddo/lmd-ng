package updater

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
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
	"github.com/dimaskiddo/lmd-ng/internal/util"
)

// Updater handles downloading and applying signature database updates.
// It supports both LMD native signatures and ClamAV CVD databases.
type Updater struct {
	cfg        *config.Config
	httpClient *http.Client
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
	// Fast internet connectivity check
	if !util.HasInternetAccess() {
		log.Warn("No internet connection detected, skipping signature updates")
		return fmt.Errorf("no internet connection")
	}

	var updated bool

	// Update LMD native signatures
	if u.cfg.Updater.AutoUpdateSignatures {
		log.Info("Checking for LMD signature updates")

		didUpdate, err := u.updateLMDSignatures(ctx)
		if err != nil {
			log.Error("LMD signature update failed", "error", err)
		} else if didUpdate {
			updated = true
		}
	}

	// Update ClamAV databases if both update and scanner are enabled
	if u.cfg.Updater.ClamAVUpdateEnabled && u.cfg.Scanner.ClamAVEnabled {
		log.Info("Checking for ClamAV database updates")

		didUpdate, err := u.updateClamAV(ctx)
		if err != nil {
			log.Error("ClamAV database update failed", "error", err)
		} else if didUpdate {
			updated = true
		}
	}

	log.Info("Update process completed", "signatures_changed", updated)
	return nil
}

// updateLMDSignatures handles downloading, verifying, and extracting new LMD signatures.
// Returns true if signatures were actually updated.
func (u *Updater) updateLMDSignatures(ctx context.Context) (bool, error) {
	currentVer, err := u.CurrentLMDVersion()
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

	// Download signature package to a temp file within the configured signatures directory
	packagePath := filepath.Join(u.cfg.App.SignaturesDir, filepath.Base(u.cfg.Updater.SignaturePackURL)+".tmp")
	if err := u.downloadFile(ctx, u.cfg.Updater.SignaturePackURL, packagePath); err != nil {
		return false, fmt.Errorf("failed to download signature package from %s: %w", u.cfg.Updater.SignaturePackURL, err)
	}
	defer os.Remove(packagePath)

	// Verify the signature pack against the CDN-published checksum. The checksum
	// URL is derived from signature_pack_url (a sibling .sha256/.md5 file), so no
	// manual configuration is required. An explicit signature_checksum_url, if
	// set, takes precedence.
	if err := u.verifySignaturePackChecksum(ctx, packagePath); err != nil {
		return false, fmt.Errorf("signature pack checksum verification failed: %w", err)
	}
	log.Info("Signature pack checksum verified")

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
	versionPath := filepath.Join(sigDirPath, versionFileName)
	tmpVersionPath := versionPath + ".tmp"

	if err := os.WriteFile(tmpVersionPath, []byte(remoteVer), 0644); err != nil {
		return false, fmt.Errorf("failed to write signature version file: %w", err)
	}

	if err := os.Rename(tmpVersionPath, versionPath); err != nil {
		os.Remove(tmpVersionPath)
		return false, fmt.Errorf("failed to rename signature version file: %w", err)
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

	// Retrieve dynamic ClamAV version from GitHub API for User-Agent
	clamAVVersion := u.getClamAVVersion(ctx)

	for _, dbName := range databases {
		select {
		case <-ctx.Done():
			return anyUpdated, ctx.Err()

		default:
		}

		downloadURL := mirrorURL + "/" + dbName
		localPath := filepath.Join(clamDBPath, dbName)

		didUpdate, err := u.downloadClamAVDatabase(ctx, downloadURL, localPath, clamAVVersion)
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
func (u *Updater) downloadClamAVDatabase(ctx context.Context, url, localPath, clamAVVersion string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create HTTP request for %s: %w", url, err)
	}

	// Use a freshclam-compatible User-Agent so the official ClamAV CDN accepts our download requests
	// The CDN checks this header and rejects clients that don't identify as ClamAV/freshclam.
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

	// Lightweight structural integrity check for CVD databases.
	if strings.HasSuffix(localPath, ".cvd") {
		if err := u.verifyCVDStructure(localPath); err != nil {
			log.Warn("CVD structure check warning (database may be corrupt)",
				"path", localPath, "error", err)
		}
	}

	log.Info("Downloaded ClamAV database", "url", url, "path", localPath)
	return true, nil
}

// CurrentLMDVersion reads the local LMD signature version file.
func (u *Updater) CurrentLMDVersion() (string, error) {
	sigDirPath := u.cfg.App.SignaturesDir

	versionFilePath := filepath.Join(sigDirPath, filepath.Base(u.cfg.Updater.SignatureVersionURL))

	data, err := os.ReadFile(versionFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to read local version file %s: %w", versionFilePath, err)
	}

	return strings.TrimSpace(string(data)), nil
}

// LastUpdateTime returns the modification time of the local version file.
// Returns zero time if the file does not exist.
func (u *Updater) LastUpdateTime() time.Time {
	sigDirPath := u.cfg.App.SignaturesDir
	versionFilePath := filepath.Join(sigDirPath, filepath.Base(u.cfg.Updater.SignatureVersionURL))

	info, err := os.Stat(versionFilePath)
	if err != nil {
		return time.Time{}
	}

	return info.ModTime()
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

// downloadText fetches a small remote file and returns its contents as a string.
func (u *Updater) downloadText(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for %s: %w", url, err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch %s returned status %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", url, err)
	}
	return string(data), nil
}

// verifySignaturePackChecksum verifies the downloaded signature pack against a
// checksum published by the upstream CDN. The checksum URL is derived from
// signature_pack_url (append the configured suffix, default ".sha256").
//
// Priority:
//  1. SignatureChecksumURL — if explicitly configured, use it verbatim.
//  2. Derived sibling URL (SignaturePackURL + SignatureChecksumSuffix).
//  3. If the derived URL returns 404, fall back to ".md5".
//
// The checksum file format is GNU checksum output: one "<hex>  <filename>" line.
func (u *Updater) verifySignaturePackChecksum(ctx context.Context, packPath string) error {
	checksumURL, expected, err := u.fetchSigpackChecksum(ctx)
	if err != nil {
		return err
	}
	if expected == "" {
		return fmt.Errorf("no checksum found for %s at %s", filepath.Base(packPath), checksumURL)
	}
	log.Debug("Sigpack checksum located", "url", checksumURL, "hash", expected[:min(16, len(expected))]+"...")

	actual, err := computeFileDigest(packPath, len(expected))
	if err != nil {
		return fmt.Errorf("cannot hash signature pack: %w", err)
	}

	if actual != expected {
		return fmt.Errorf("signature pack checksum mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

// fetchSigpackChecksum returns the checksum URL and expected hex digest for the
// signature pack, trying sources in priority order (explicit URL, derived
// suffix, .md5 fallback). Returns an error when no reachable source lists the
// pack filename.
func (u *Updater) fetchSigpackChecksum(ctx context.Context) (url, expected string, err error) {
	base := filepath.Base(u.cfg.Updater.SignaturePackURL)

	var candidates []string
	if u.cfg.Updater.SignatureChecksumURL != "" {
		candidates = append(candidates, u.cfg.Updater.SignatureChecksumURL)
	}
	if s := u.cfg.Updater.SignatureChecksumSuffix; s != "" {
		candidates = append(candidates, u.cfg.Updater.SignaturePackURL+s)
	}
	// MD5 fallback when the stronger .sha256 sibling is unavailable.
	candidates = append(candidates, u.cfg.Updater.SignaturePackURL+".md5")

	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		data, err := u.downloadText(ctx, cand)
		if err != nil {
			continue // try next candidate
		}
		hex, ok := parseChecksumLine(data, base)
		if !ok {
			continue
		}
		// SHA-256 digests are 64 hex chars; MD5 are 32.
		switch len(hex) {
		case 64, 32:
			return cand, hex, nil
		}
	}

	return "", "", fmt.Errorf("no checksum source available for %s", base)
}

// parseChecksumLine extracts the lowercase hex digest for a filename from GNU
// checksum output ("<hex>  <filename>" per line). Returns ok=false when the
// file is not listed.
func parseChecksumLine(data, filename string) (string, bool) {
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 && strings.TrimSuffix(parts[1], "\t") == filename {
			return strings.ToLower(parts[0]), true
		}
	}
	return "", false
}

// computeFileDigest hashes the file with the algorithm implied by expectedLen:
// 64 → SHA-256, 32 → MD5. Returns the lowercase hex digest.
func computeFileDigest(path string, expectedLen int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	switch expectedLen {
	case 64:
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		return fmt.Sprintf("%x", h.Sum(nil)), nil
	case 32:
		h := md5.New()
		if _, err := io.Copy(h, f); err != nil {
			return "", err
		}
		return fmt.Sprintf("%x", h.Sum(nil)), nil
	default:
		return "", fmt.Errorf("unsupported digest length %d", expectedLen)
	}
}

// verifyCVDStructure performs a lightweight structural check on a ClamAV CVD
// file: the 512-byte header must carry the "ClamAV-VDB" magic. The full
// cryptographic integrity check is done by pkg/clamav when the database is
// loaded. This catches truncated or corrupt downloads early.
func (u *Updater) verifyCVDStructure(cvdPath string) error {
	f, err := os.Open(cvdPath)
	if err != nil {
		return fmt.Errorf("cannot open CVD file: %w", err)
	}
	defer f.Close()

	header := make([]byte, 512)
	n, err := io.ReadFull(f, header)
	if err != nil && err != io.ErrUnexpectedEOF {
		return fmt.Errorf("cannot read CVD header: %w", err)
	}

	headerStr := strings.TrimRight(string(header[:n]), "\x00 \n\r\t")
	if !strings.HasPrefix(headerStr, "ClamAV-VDB") {
		return fmt.Errorf("CVD header missing ClamAV-VDB magic: %q", headerStr)
	}
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
		// Tar entries always use forward slashes regardless of OS
		sigDirName := filepath.ToSlash(filepath.Base(u.cfg.App.SignaturesDir)) + "/"
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

			tmpPath := targetPath + ".tmp"
			outFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("failed to create temp file %s: %w", tmpPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				os.Remove(tmpPath)
				return fmt.Errorf("failed to write file content to %s: %w", tmpPath, err)
			}

			outFile.Sync()
			outFile.Close()

			if err := os.Rename(tmpPath, targetPath); err != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("failed to rename temp file to %s: %w", targetPath, err)
			}

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

// getClamAVVersion dynamically fetches the latest ClamAV release version
// from GitHub API to bypass the CDN restriction. Falls back to a hardcoded
// version if the request fails or is rate-limited.
func (u *Updater) getClamAVVersion(ctx context.Context) string {
	defaultVersion := "1.5.2"

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest", nil)
	if err != nil {
		return defaultVersion
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	// Set a shorter timeout specifically for the API call to avoid hanging
	// the whole update process if GitHub API is slow.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Debug("Failed to fetch ClamAV version from GitHub API, using fallback", "error", err)
		return defaultVersion
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Debug("GitHub API returned non-OK status, using fallback", "status", resp.StatusCode)
		return defaultVersion
	}

	var result struct {
		TagName string `json:"tag_name"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Debug("Failed to decode GitHub API response, using fallback", "error", err)
		return defaultVersion
	}

	version := strings.TrimPrefix(result.TagName, "clamav-")
	version = strings.TrimPrefix(version, "v")

	if version == "" {
		return defaultVersion
	}

	log.Debug("Fetched latest ClamAV version from GitHub API", "version", version)
	return version
}
