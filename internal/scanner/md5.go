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

// md5Scanner loads and checks MD5 signatures.
type md5Scanner struct {
	signatures     map[string]string
	allowlistPaths []string
}

// newMD5Scanner creates and initializes a new MD5 scanner.
func newMD5Scanner(cfg *config.Config) (*md5Scanner, error) {
	s := &md5Scanner{
		signatures:     make(map[string]string),
		allowlistPaths: cfg.Scanner.HashAllowlistPaths,
	}

	datDir := filepath.Join(cfg.App.SignaturesDir, "dat")
	entries, err := os.ReadDir(datDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasPrefix(entry.Name(), "md5") && strings.HasSuffix(entry.Name(), ".dat") {
				filePath := filepath.Join(datDir, entry.Name())
				if err := s.loadSignatures(filePath); err != nil {
					log.Warn("Failed to load MD5 signatures", "file", filePath, "error", err)
				}
			}
		}
	} else {
		log.Warn("Failed to read dat signatures directory", "dir", datDir, "error", err)
	}

	customSigPath := filepath.Join(cfg.App.SignaturesDir, "custom.md5")
	if err := s.loadSignatures(customSigPath); err != nil {
		if os.IsNotExist(err) {
			log.Debug("No custom MD5 signatures found", "error", err)
		} else {
			log.Warn("Failed to load custom MD5 signatures", "error", err)
		}
	}

	return s, nil
}

// loadSignatures reads a signature file and populates the internal map.
func (s *md5Scanner) loadSignatures(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("MD5 signature file not found, skipping load", "file", filePath)
			return nil
		}

		return fmt.Errorf("failed to open MD5 signature file %s: %w", filePath, err)
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
			log.Debug("Invalid MD5 signature format", "line", line, "file", filePath)
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

		if len(hash) != 32 {
			log.Debug("Invalid MD5 hash length", "hash", hash, "file", filePath)
			continue
		}

		s.signatures[hash] = name
	}

	if err := scanner.Err(); err != nil {
		log.Warn("Scanner error while loading MD5 signatures", "file", filePath, "error", err)
	}

	log.Info("Loaded MD5 signatures", "count", len(s.signatures)-sigsBefore, "file", filePath)
	return nil
}

// Count returns the number of loaded MD5 signatures.
func (s *md5Scanner) Count() int {
	return len(s.signatures)
}

// Check returns the signature name if the MD5 hash matches a known signature,
// or "" if suppressed by the path allowlist.
func (s *md5Scanner) Check(md5Hash, filePath string) string {
	name := s.signatures[md5Hash]
	if name == "" {
		return ""
	}

	for _, prefix := range s.allowlistPaths {
		if strings.HasPrefix(filePath, prefix) {
			log.Warn("MD5 hash match suppressed by system-path allowlist",
				"file", filePath,
				"signature", name,
				"allowlist_prefix", prefix)
			return ""
		}
	}

	return name
}
