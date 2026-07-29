package scanner

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// hexSignatureEntry represents a single hex pattern signature.
type hexSignatureEntry struct {
	pattern       []byte         // Hex pattern decoded to bytes (wildcard positions = 0x00)
	fixed         bool           // True if no wildcards — fast bytes.Contains path
	hasWildcards  bool           // True if pattern contains ?? wildcards
	wildcardPos   []int          // Byte offsets in pattern where ?? appears (0 = any byte)
	wildcardCount int            // Number of ?? wildcards
	patternStr    string         // Original hex string for regex fallback
	name          string         // Name of the signature
}

// hexScanner is responsible for loading and checking hex signatures.
type hexScanner struct {
	signatures []hexSignatureEntry
}

// newHexScanner creates and initializes a new hex scanner.
func newHexScanner(cfg *config.Config) (*hexScanner, error) {
	s := &hexScanner{
		// Pre-allocate with reasonable initial capacity; no hard limit —
		// append() grows the slice unboundedly for large signature sets.
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

	// Load custom user hex signatures if they exist
	customSigPath := filepath.Join(cfg.App.SignaturesDir, "custom.hex")
	if err := s.loadSignatures(customSigPath); err != nil {
		log.Debug("No custom HEX signatures found or failed to load", "error", err)
	}

	return s, nil
}

// loadSignatures reads a signature file and populates the internal slice.
// Supports two formats:
//   - Maldet: s^hex_string^signature_name^threat_level (caret-delimited)
//   - Legacy: hex_string:signature_name (colon-delimited)
//
// Hex patterns support the following wildcard syntax:
//   - "??": match any single byte (wildcard nibble pair)
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

	// Buffer: initial 64KB, max 1MB per line. This limits individual line
	// length, NOT the total number of signatures — all lines are still read.
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	loaded := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		var patternHex, sigName string

		// Support Maldet caret format: s^hex^name^level
		if strings.HasPrefix(line, "s^") {
			parts := strings.SplitN(line[2:], "^", 3)
			if len(parts) < 2 {
				log.Debug("Invalid HEX signature format (caret)", "line", line, "file", filePath)
				continue
			}

			patternHex = strings.TrimSpace(parts[0])
			sigName = strings.TrimSpace(parts[1])
			// parts[2] = threat_level — parsed but unused (matches Maldet behavior)
		} else {
			// Legacy colon format: hex:name
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

		// Reject signatures with fewer than 4 static bytes — too short to be
		// specific, high false positive risk across unrelated files.
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

	log.Info("Loaded HEX signatures", "count", loaded, "file", filePath)
	return nil
}

// compileHexSignature decodes a hex pattern string (potentially with ?? wildcards)
// into a hexSignatureEntry with wildcard position tracking.
func compileHexSignature(patternHex, name string) (*hexSignatureEntry, error) {
	if len(patternHex) == 0 {
		return nil, fmt.Errorf("empty hex pattern")
	}

	// Must have even number of characters for valid hex
	if len(patternHex)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex pattern")
	}

	// Check if any wildcard nibbles exist
	hasWildcards := false
	for i := 0; i < len(patternHex); i++ {
		if patternHex[i] == '?' {
			hasWildcards = true
			break
		}
	}

	if !hasWildcards {
		// Simple fixed hex — use fast bytes.Contains path
		decoded, err := hex.DecodeString(patternHex)
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex pattern: %w", err)
		}

		return &hexSignatureEntry{
			pattern:       decoded,
			fixed:         true,
			hasWildcards:  false,
			patternStr:    patternHex,
			name:          name,
		}, nil
	}

	// Pattern has wildcards — decode fixed bytes and record wildcard positions.
	// Each hex pair (2 chars) represents one byte. "?? = any byte at that position.
	pattern := make([]byte, len(patternHex)/2)
	var wildcardPos []int
	hasComplexWildcards := false

	for i := 0; i < len(patternHex); i += 2 {
		byteIdx := i / 2
		high := patternHex[i]
		low := patternHex[i+1]

		if high == '?' && low == '?' {
			pattern[byteIdx] = 0x00 // placeholder — any byte matches
			wildcardPos = append(wildcardPos, byteIdx)
		} else if high == '?' || low == '?' {
			// Nibble wildcard (a? or ?a) — not supported in LMD hex path
			// These patterns belong in RFXN NDB which has full nibble support
			hasComplexWildcards = true
		} else if high == '*' || low == '*' {
			// Unbounded wildcard — not supported in LMD hex path
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

	// Reject all-wildcard patterns — they match everything (high false positive risk)
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

// hexWildcardMatch checks if content contains the pattern, allowing ?? bytes
// at wildcard positions. Uses a sliding-window scan of fixed segments.
func hexWildcardMatch(content []byte, sig *hexSignatureEntry) bool {
	// Split pattern into fixed segments at wildcard boundaries.
	// A pattern like "dead??beef" becomes segments: [dead, beef]
	// with wildcardCount=1 and wildcardPos=[2].
	type segment struct {
		data   []byte
		offset int // byte offset in original pattern
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

	// No fixed segments — ?? pattern matches everything
	if len(segments) == 0 {
		return true
	}

	// Find the first fixed segment to anchor the search
	firstSeg := segments[0]
	startPos := 0

	for {
		// Find next occurrence of first segment in content
		idx := bytes.Index(content[startPos:], firstSeg.data)
		if idx < 0 {
			return false
		}

		matchStart := startPos + idx
		fullMatch := true

		// Verify subsequent segments at their expected positions
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

		// Move past current match position and try next occurrence
		startPos = matchStart + 1
	}
}

// Count returns the number of loaded HEX signatures.
func (s *hexScanner) Count() int {
	return len(s.signatures)
}

// Check searches the given content for any loaded hex signatures and returns their names.
//
// False-positive guard: if the file's content begins with a native-executable
// magic header (ELF or Mach-O), any signature whose name does NOT start with
// a known Unix-targeted prefix (e.g. "Unix.", "Linux.") is skipped. This
// prevents Windows-specific hex patterns from matching against Linux shared
// libraries or macOS dylibs. LMD hex.dat contains predominantly Windows
// signatures — non-Unix-targeted sigs on a non-Windows binary are the common
// case, not the edge.
func (s *hexScanner) Check(content []byte, filePath string) []string {
	detectedType := detectMagicType(content)
	nativeExec := isNativeExecutable(detectedType)

	var matchedSigs []string
	for _, sig := range s.signatures {
		// Skip non-Unix signatures when scanning native executables (ELF/Mach-O).
		// Only keep signatures explicitly targeting Unix/macOS platforms.
		if nativeExec && !isUnixTargetedSig(sig.name) {
			log.Debug("Skipping non-Unix HEX signature on native executable",
				"signature", sig.name,
				"file", filePath,
				"detected_type", detectedType)
			continue
		}

		if sig.fixed {
			// Fast path: no wildcards — direct byte comparison
			if bytes.Contains(content, sig.pattern) {
				matchedSigs = append(matchedSigs, sig.name)
			}
		} else if sig.hasWildcards {
			// Wildcard path: ??-aware matching
			if hexWildcardMatch(content, &sig) {
				matchedSigs = append(matchedSigs, sig.name)
			}
		}
	}

	return matchedSigs
}

// hexWildcardMatchRegex is an alternative regex-based matcher for complex patterns.
// Currently unused — the segment-based matcher above is faster for ?? wildcards.
// Kept for future use if nibble wildcards or {n-m} ranges are needed.
func hexWildcardMatchRegex(content []byte, patternHex string) bool {
	// Convert ClamAV hex to Go regex (reusing pkg/clamav's approach)
	regexStr := clamHexToGoRegex(patternHex)
	if regexStr == "" {
		return false
	}

	re, err := regexp.Compile(regexStr)
	if err != nil {
		return false
	}

	return re.Match(content)
}

// clamHexToGoRegex converts a ClamAV-style hex pattern to a Go byte regex.
// Handles: ?? → ., hex pairs → literal bytes, nibble wildcards → character classes.
func clamHexToGoRegex(patternHex string) string {
	var result strings.Builder
	result.WriteString("(?s)")

	for i := 0; i < len(patternHex); {
		if i+1 >= len(patternHex) {
			break
		}

		high := patternHex[i]
		low := patternHex[i+1]

		switch {
		case high == '?' && low == '?':
			result.WriteString("(?s:.)")
			i += 2

		case high == '?':
			// Low nibble fixed — 16 possible bytes
			lowVal, ok := hexNibbleValue(low)
			if !ok {
				return ""
			}

			result.WriteByte('(')
			for h := byte(0); h < 16; h++ {
				if h > 0 {
					result.WriteByte('|')
				}

				result.WriteString(fmt.Sprintf("\\x%02x", (h<<4)|lowVal))
			}

			result.WriteByte(')')
			i += 2

		case low == '?':
			// High nibble fixed — 16 possible bytes
			highVal, ok := hexNibbleValue(high)
			if !ok {
				return ""
			}

			lowByte := highVal << 4
			highByte := (highVal << 4) | 15
			result.WriteString(fmt.Sprintf("[\\x%02x-\\x%02x]", lowByte, highByte))
			i += 2

		default:
			v, err := hex.DecodeString(string([]byte{high, low}))
			if err != nil {
				return ""
			}

			result.WriteString(fmt.Sprintf("\\x%02x", v[0]))
			i += 2
		}
	}

	return result.String()
}

// hexNibbleValue converts a hex character to its numeric value (0-15).
func hexNibbleValue(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
