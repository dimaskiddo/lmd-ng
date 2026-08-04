package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// hexSignatureEntry represents a single hex pattern signature.
type hexSignatureEntry struct {
	pattern       []byte
	fixed         bool
	hasWildcards  bool
	wildcardPos   []int
	wildcardCount int
	patternStr    string
	name          string
}

// hexScanner is responsible for loading and checking hex signatures.
type hexScanner struct {
	signatures []hexSignatureEntry
}

// newHexScanner creates and initializes a new hex scanner.
func newHexScanner(cfg *config.Config) (*hexScanner, error) {
	s := &hexScanner{
		signatures: make([]hexSignatureEntry, 0, 50000),
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

	customSigPath := filepath.Join(cfg.App.SignaturesDir, "custom.hex")
	if err := s.loadSignatures(customSigPath); err != nil {
		if os.IsNotExist(err) {
			log.Debug("No custom HEX signatures found", "error", err)
		} else {
			log.Warn("Failed to load custom HEX signatures", "error", err)
		}
	}

	return s, nil
}

// loadSignatures reads a signature file and populates the internal slice.
// Supports Maldet caret (s^hex^name^level) and legacy colon (hex:name) formats.
func (s *hexScanner) loadSignatures(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info("HEX signature file not found, skipping load", "file", filePath)
			return nil
		}

		return fmt.Errorf("failed to open HEX signature file %s: %w", filePath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	loaded := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		var patternHex, sigName string

		if strings.HasPrefix(line, "s^") {
			parts := strings.SplitN(line[2:], "^", 3)
			if len(parts) < 2 {
				log.Debug("Invalid HEX signature format (caret)", "line", line, "file", filePath)
				continue
			}

			patternHex = strings.TrimSpace(parts[0])
			sigName = strings.TrimSpace(parts[1])
		} else {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				log.Debug("Invalid HEX signature format (colon)", "line", line, "file", filePath)
				continue
			}

			patternHex = strings.TrimSpace(parts[0])
			sigName = strings.TrimSpace(parts[1])
		}

		sig, err := compileHexSignature(patternHex, sigName)
		if err != nil {
			log.Debug("Invalid HEX pattern in signature", "pattern_hex", patternHex, "error", err, "file", filePath)
			continue
		}

		if !sig.fixed {
			staticBytes := len(sig.pattern) - len(sig.wildcardPos)
			if staticBytes < 4 {
				log.Warn("HEX signature too short, skipping (high false positive risk)",
					"name", sig.name, "static_bytes", staticBytes, "file", filePath)
				continue
			}
		}

		s.signatures = append(s.signatures, *sig)
		loaded++
	}

	if err := scanner.Err(); err != nil {
		log.Warn("Scanner error while loading HEX signatures", "file", filePath, "error", err)
	}

	log.Info("Loaded HEX signatures", "count", loaded, "file", filePath)
	return nil
}

// compileHexSignature decodes a hex pattern (with optional ?? wildcards) into
// a hexSignatureEntry.
func compileHexSignature(patternHex, name string) (*hexSignatureEntry, error) {
	if len(patternHex) == 0 {
		return nil, fmt.Errorf("empty hex pattern")
	}

	if len(patternHex)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex pattern")
	}

	hasWildcards := false
	for i := 0; i < len(patternHex); i++ {
		if patternHex[i] == '?' {
			hasWildcards = true
			break
		}
	}

	if !hasWildcards {
		decoded, err := hex.DecodeString(patternHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex pattern: %w", err)
		}

		return &hexSignatureEntry{
			pattern:      decoded,
			fixed:        true,
			hasWildcards: false,
			patternStr:   patternHex,
			name:         name,
		}, nil
	}

	pattern := make([]byte, len(patternHex)/2)
	var wildcardPos []int
	hasComplexWildcards := false

	for i := 0; i < len(patternHex); i += 2 {
		byteIdx := i / 2
		high := patternHex[i]
		low := patternHex[i+1]

		if high == '?' && low == '?' {
			pattern[byteIdx] = 0x00
			wildcardPos = append(wildcardPos, byteIdx)
		} else if high == '?' || low == '?' {
			hasComplexWildcards = true
		} else if high == '*' || low == '*' {
			hasComplexWildcards = true
		} else {
			v, err := hex.DecodeString(string([]byte{high, low}))
			if err != nil {
				return nil, fmt.Errorf("failed to decode hex pair '%c%c' at position %d: %w", high, low, i, err)
			}

			pattern[byteIdx] = v[0]
		}
	}

	if hasComplexWildcards {
		return nil, fmt.Errorf("complex wildcards (nibble, *, {}) not supported in LMD hex — use RFXN NDB")
	}

	if len(wildcardPos) == len(pattern) {
		return nil, fmt.Errorf("pattern has no fixed bytes (all wildcards)")
	}

	return &hexSignatureEntry{
		pattern:       pattern,
		fixed:         false,
		hasWildcards:  true,
		wildcardPos:   wildcardPos,
		wildcardCount: len(wildcardPos),
		patternStr:    patternHex,
		name:          name,
	}, nil
}

// hexWildcardMatch reports whether content contains the pattern, allowing any
// byte at wildcard positions.
func hexWildcardMatch(content []byte, sig *hexSignatureEntry) bool {
	type segment struct {
		data   []byte
		offset int
	}

	var segments []segment
	segStart := 0
	inSeg := true

	for i := 0; i < len(sig.pattern); i++ {
		isWildcard := false
		for _, wp := range sig.wildcardPos {
			if i == wp {
				isWildcard = true
				break
			}
		}

		if isWildcard {
			if inSeg && i > segStart {
				segments = append(segments, segment{data: sig.pattern[segStart:i], offset: segStart})
			}

			inSeg = false
		} else {
			if !inSeg {
				segStart = i
				inSeg = true
			}
		}
	}

	if inSeg && segStart < len(sig.pattern) {
		segments = append(segments, segment{data: sig.pattern[segStart:], offset: segStart})
	}

	if len(segments) == 0 {
		return true
	}

	firstSeg := segments[0]
	startPos := 0

	for {
		idx := bytes.Index(content[startPos:], firstSeg.data)
		if idx < 0 {
			return false
		}

		matchStart := startPos + idx
		fullMatch := true

		for _, seg := range segments[1:] {
			expectedPos := matchStart + seg.offset
			if expectedPos+len(seg.data) > len(content) {
				fullMatch = false
				break
			}

			if !bytes.Equal(content[expectedPos:expectedPos+len(seg.data)], seg.data) {
				fullMatch = false
				break
			}
		}

		if fullMatch {
			return true
		}

		startPos = matchStart + 1
	}
}

// Count returns the number of loaded HEX signatures.
func (s *hexScanner) Count() int {
	return len(s.signatures)
}

// Check returns the names of any loaded hex signatures found in content.
func (s *hexScanner) Check(ctx context.Context, content []byte, filePath string) []string {
	detectedType := detectMagicType(content)
	nativeExec := isNativeExecutable(detectedType)

	var matchedSigs []string
	for _, sig := range s.signatures {
		select {
		case <-ctx.Done():
			return matchedSigs
		default:
		}

		if nativeExec && !isUnixTargetedSig(sig.name) {
			log.Debug("Skipping non-Unix HEX signature on native executable",
				"signature", sig.name,
				"file", filePath,
				"detected_type", detectedType)
			continue
		}

		if sig.fixed {
			if bytes.Contains(content, sig.pattern) {
				matchedSigs = append(matchedSigs, sig.name)
			}
		} else if sig.hasWildcards {
			if hexWildcardMatch(content, &sig) {
				matchedSigs = append(matchedSigs, sig.name)
			}
		}
	}

	return matchedSigs
}
