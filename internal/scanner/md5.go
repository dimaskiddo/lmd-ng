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

// md5Scanner is responsible for loading and checking MD5 signatures.
type md5Scanner struct {
	signatures map[string]string // md5 hash (lowercase) -> signature name
}

// NewMD5Scanner creates and initializes a new MD5 scanner.
func NewMD5Scanner(cfg *config.Config) (*md5Scanner, error) {
	s := &md5Scanner{
		signatures: make(map[string]string),
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

	// Load custom user MD5 signatures if they exist
	customSigPath := filepath.Join(cfg.App.SignaturesDir, "custom.md5")
	if err := s.loadSignatures(customSigPath); err != nil {
		log.Debug("No custom MD5 signatures found or failed to load", "error", err)
	}

	return s, nil
}

// loadSignatures reads a signature file and populates the internal map.
func (s *md5Scanner) loadSignatures(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		// If the file doesn't exist, it's not an error, just means no signatures to load
		if os.IsNotExist(err) {
			log.Info("MD5 signature file not found, skipping load", "file", filePath)
			return nil
		}

		return fmt.Errorf("failed to open MD5 signature file %s: %w", filePath, err)
	}
	defer file.Close()

	reader := bytes.NewBuffer(make([]byte, 0, 1024*1024)) // 1MB buffer
	if _, err := io.Copy(reader, file); err != nil {
		return fmt.Errorf("failed to read MD5 signature file %s content: %w", filePath, err)
	}

	lines := strings.Split(reader.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
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
			// Check if parts[1] is a numeric file size (md5v2.dat format)
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

		if len(hash) != 32 {
			log.Debug("Invalid MD5 hash length", "hash", hash, "file", filePath)
			continue
		}

		s.signatures[hash] = name
	}

	log.Info("Loaded MD5 signatures", "count", len(s.signatures), "file", filePath)
	return nil
}

// Check returns the signature name if the MD5 hash matches a known signature.
func (s *md5Scanner) Check(md5Hash string) string {
	return s.signatures[strings.ToLower(md5Hash)]
}
