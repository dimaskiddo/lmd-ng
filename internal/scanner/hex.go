package scanner

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// hexSignatureEntry represents a single hex pattern signature.
type hexSignatureEntry struct {
	pattern []byte // Hex pattern decoded to bytes
	name    string // Name of the signature
}

// hexScanner is responsible for loading and checking hex signatures.
type hexScanner struct {
	signatures []hexSignatureEntry
}

// NewHexScanner creates and initializes a new hex scanner.
func NewHexScanner(cfg *config.Config) (*hexScanner, error) {
	s := &hexScanner{
		signatures: make([]hexSignatureEntry, 0),
	}

	datDir := filepath.Join(cfg.App.SignaturesDir, "dat")
	entries, err := os.ReadDir(datDir)
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasPrefix(entry.Name(), "hex") && strings.HasSuffix(entry.Name(), ".dat") {
				filePath := filepath.Join(datDir, entry.Name())
				if err := s.loadSignatures(filePath); err != nil {
					log.Warn("Failed to load HEX signatures", "file", filePath, "error", err)
				}
			}
		}
	} else {
		log.Warn("Failed to read dat signatures directory", "dir", datDir, "error", err)
	}

	// Load custom user hex signatures if they exist
	customSigPath := filepath.Join(cfg.App.SignaturesDir, "custom.hex")
	if err := s.loadSignatures(customSigPath); err != nil {
		log.Debug("No custom HEX signatures found or failed to load", "error", err)
	}

	return s, nil
}

// loadSignatures reads a signature file and populates the internal slice.
func (s *hexScanner) loadSignatures(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		// If the file doesn't exist, it's not an error, just means no signatures to load
		if os.IsNotExist(err) {
			log.Info("HEX signature file not found, skipping load", "file", filePath)
			return nil
		}

		return fmt.Errorf("failed to open HEX signature file %s: %w", filePath, err)
	}
	defer file.Close()

	// Read file content in chunks to avoid loading large files entirely into memory
	// A larger buffer might be needed for very large signature files, but 1MB is a reasonable start.
	reader := bytes.NewBuffer(make([]byte, 0, 1024*1024))
	if _, err := io.Copy(reader, file); err != nil {
		return fmt.Errorf("failed to read HEX signature file %s content: %w", filePath, err)
	}

	lines := strings.Split(reader.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) < 2 {
			log.Debug("Invalid HEX signature format", "line", line, "file", filePath)
			continue
		}

		patternHex := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])

		pattern, err := hex.DecodeString(patternHex)
		if err != nil {
			log.Debug("Invalid HEX pattern in signature", "pattern_hex", patternHex, "error", err, "file", filePath)
			continue
		}

		s.signatures = append(s.signatures, hexSignatureEntry{
			pattern: pattern,
			name:    name,
		})
	}

	log.Info("Loaded HEX signatures", "count", len(s.signatures), "file", filePath)
	return nil
}

// Check searches the given content for any loaded hex signatures and returns their names.
func (s *hexScanner) Check(content []byte) []string {
	var matchedSigs []string
	for _, sig := range s.signatures {
		if bytes.Contains(content, sig.pattern) {
			matchedSigs = append(matchedSigs, sig.name)
		}
	}

	return matchedSigs
}
