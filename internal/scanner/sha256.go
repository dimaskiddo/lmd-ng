package scanner

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// sha256Scanner is responsible for loading and checking SHA256 signatures.
type sha256Scanner struct {
	signatures     map[string]string // sha256 hash (lowercase) -> signature name
	allowlistPaths []string          // path prefixes whose files are exempt from hash matching
}

// NewSHA256Scanner creates and initializes a new SHA256 scanner.
func NewSHA256Scanner(cfg *config.Config) (*sha256Scanner, error) {
	s := &sha256Scanner{
		signatures:     make(map[string]string),
		allowlistPaths: cfg.Scanner.HashAllowlistPaths,
	}

	datDir := filepath.Join(cfg.App.SignaturesDir, "dat")
	entries, err := os.ReadDir(datDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasPrefix(entry.Name(), "sha256") && strings.HasSuffix(entry.Name(), ".dat") {
				filePath := filepath.Join(datDir, entry.Name())
				if err := s.loadSignatures(filePath); err != nil {
					log.Warn("Failed to load SHA256 signatures", "file", filePath, "error", err)
				}
			}
		}
	} else {
		log.Warn("Failed to read dat signatures directory", "dir", datDir, "error", err)
	}

	// Load custom user SHA256 signatures if they exist
	customSigPath := filepath.Join(cfg.App.SignaturesDir, "custom.sha256")
	if err := s.loadSignatures(customSigPath); err != nil {
		log.Debug("No custom SHA256 signatures found or failed to load", "error", err)
	}

	return s, nil
}

// loadSignatures reads a signature file and populates the internal map.
func (s *sha256Scanner) loadSignatures(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		// If the file doesn't exist, it's not an error, just means no signatures to load
		if os.IsNotExist(err) {
			log.Info("SHA256 signature file not found, skipping load", "file", filePath)
			return nil
		}

		return fmt.Errorf("failed to open SHA256 signature file %s: %w", filePath, err)
	}
	defer file.Close()

	reader := bytes.NewBuffer(make([]byte, 0, 1024*1024)) // 1MB buffer
	if _, err := io.Copy(reader, file); err != nil {
		return fmt.Errorf("failed to read SHA256 signature file %s content: %w", filePath, err)
	}

	lines := strings.Split(reader.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 2 {
			log.Debug("Invalid SHA256 signature format", "line", line, "file", filePath)
			continue
		}

		hash := strings.ToLower(strings.TrimSpace(parts[0]))
		var name string

		if len(parts) == 3 {
			// Check if parts[1] is a numeric file size (sha256v2.dat format)
			isNumeric := true
			for _, c := range strings.TrimSpace(parts[1]) {
				if c < '0' || c > '9' {
					isNumeric = false
					break
				}
			}

			if isNumeric && strings.TrimSpace(parts[1]) != "" {
				name = strings.TrimSpace(parts[2])
			} else {
				// It's likely hash:name where the name contains a colon
				name = strings.TrimSpace(parts[1]) + ":" + strings.TrimSpace(parts[2])
			}
		} else {
			name = strings.TrimSpace(parts[1])
		}

		if len(hash) != 64 {
			log.Debug("Invalid SHA256 hash length", "hash", hash, "file", filePath)
			continue
		}

		s.signatures[hash] = name
	}

	log.Info("Loaded SHA256 signatures", "count", len(s.signatures), "file", filePath)
	return nil
}

// Check returns the signature name if the SHA256 hash matches a known signature.
//
// System-path allowlist guard: if filePath starts with any configured
// allowlist prefix, the detection is suppressed and an empty string is
// returned. This prevents a bad signature database from falsely flagging
// legitimate system files (e.g. /usr/bin/sudo, /usr/lib/*.so).
func (s *sha256Scanner) Check(sha256Hash, filePath string) string {
	name := s.signatures[strings.ToLower(sha256Hash)]
	if name == "" {
		return ""
	}

	// Check if the file path is under any allowlisted prefix
	for _, prefix := range s.allowlistPaths {
		if strings.HasPrefix(filePath, prefix) {
			log.Warn("SHA256 hash match suppressed by system-path allowlist",
				"file", filePath,
				"signature", name,
				"allowlist_prefix", prefix)
			return ""
		}
	}

	return name
}
