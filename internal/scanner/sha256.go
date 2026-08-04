package scanner

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// sha256Scanner loads and checks SHA256 signatures.
type sha256Scanner struct {
	signatures     map[string]string
	allowlistPaths []string
}

// newSHA256Scanner creates and initializes a new SHA256 scanner.
func newSHA256Scanner(cfg *config.Config) (*sha256Scanner, error) {
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

	customSigPath := filepath.Join(cfg.App.SignaturesDir, "custom.sha256")
	if err := s.loadSignatures(customSigPath); err != nil {
		if os.IsNotExist(err) {
			log.Debug("No custom SHA256 signatures found", "error", err)
		} else {
			log.Warn("Failed to load custom SHA256 signatures", "error", err)
		}
	}

	return s, nil
}

// loadSignatures reads a signature file and populates the internal map.
func (s *sha256Scanner) loadSignatures(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("SHA256 signature file not found, skipping load", "file", filePath)
			return nil
		}

		return fmt.Errorf("failed to open SHA256 signature file %s: %w", filePath, err)
	}
	defer file.Close()

	sigsBefore := len(s.signatures)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
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
			if _, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && strings.TrimSpace(parts[1]) != "" {
				name = strings.TrimSpace(parts[2])
			} else {
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

	if err := scanner.Err(); err != nil {
		log.Warn("Scanner error while loading SHA256 signatures", "file", filePath, "error", err)
	}

	log.Info("Loaded SHA256 signatures", "count", len(s.signatures)-sigsBefore, "file", filePath)
	return nil
}

// Count returns the number of loaded SHA256 signatures.
func (s *sha256Scanner) Count() int {
	return len(s.signatures)
}

// Check returns the signature name if the SHA256 hash matches a known signature,
// or "" if suppressed by the path allowlist.
func (s *sha256Scanner) Check(sha256Hash, filePath string) string {
	name := s.signatures[sha256Hash]
	if name == "" {
		return ""
	}

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
