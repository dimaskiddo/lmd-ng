package clamav

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
)

// NDB TargetType constants as defined by the ClamAV signature specification.
// See: https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html
const (
	// NDBTargetAny matches any file type.
	NDBTargetAny = 0
	// NDBTargetPE matches Windows PE executables (MZ/PE magic).
	NDBTargetPE = 1
	// NDBTargetOLE2 matches Microsoft OLE2 compound documents (Office files, etc.).
	NDBTargetOLE2 = 2
	// NDBTargetHTML matches HTML files.
	NDBTargetHTML = 3
	// NDBTargetMail matches e-mail files.
	NDBTargetMail = 4
	// NDBTargetGraphics matches graphics files.
	NDBTargetGraphics = 5
	// NDBTargetELF matches ELF executables and shared libraries (Linux/Unix).
	NDBTargetELF = 6
	// NDBTargetASCII matches ASCII/plain-text files.
	NDBTargetASCII = 7
	// NDBTargetMachO matches Mach-O executables (macOS/iOS).
	NDBTargetMachO = 9
)

// Magic byte sequences used to detect file type for NDB TargetType filtering.
var (
	// magicMZ is the DOS/PE executable header ("MZ").
	magicMZ = []byte{0x4D, 0x5A}
	// magicELF is the ELF executable/library header ("\x7fELF").
	magicELF = []byte{0x7F, 0x45, 0x4C, 0x46}
	// magicOLE2 is the OLE2 compound document header.
	magicOLE2 = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}
	// magicMachO32 is the Mach-O 32-bit little-endian magic.
	magicMachO32 = []byte{0xCE, 0xFA, 0xED, 0xFE}
	// magicMachO64 is the Mach-O 64-bit little-endian magic.
	magicMachO64 = []byte{0xCF, 0xFA, 0xED, 0xFE}
	// magicMachO32BE is the Mach-O 32-bit big-endian magic.
	magicMachO32BE = []byte{0xFE, 0xED, 0xFA, 0xCE}
	// magicMachO64BE is the Mach-O 64-bit big-endian magic.
	magicMachO64BE = []byte{0xFE, 0xED, 0xFA, 0xCF}
)

// detectFileType inspects the first bytes of content to determine the ClamAV
// NDB TargetType. Returns NDBTargetAny (0) when the type cannot be determined.
func detectFileType(content []byte) int {
	if len(content) < 2 {
		return NDBTargetAny
	}

	// ELF: \x7fELF — must be checked before PE because some linkers embed MZ stubs.
	if len(content) >= 4 && bytes.HasPrefix(content, magicELF) {
		return NDBTargetELF
	}

	// Windows PE / DOS executable: MZ header.
	if bytes.HasPrefix(content, magicMZ) {
		return NDBTargetPE
	}

	// OLE2 compound document.
	if len(content) >= 8 && bytes.HasPrefix(content, magicOLE2) {
		return NDBTargetOLE2
	}

	// Mach-O (any endianness / bitness).
	if len(content) >= 4 {
		prefix4 := content[:4]
		if bytes.Equal(prefix4, magicMachO32) || bytes.Equal(prefix4, magicMachO64) ||
			bytes.Equal(prefix4, magicMachO32BE) || bytes.Equal(prefix4, magicMachO64BE) {
			return NDBTargetMachO
		}
	}

	// Fallback: treat as generic / any.
	return NDBTargetAny
}

// NDBSignature represents a single ClamAV NDB (body/extended) signature.
type NDBSignature struct {
	Name       string         // Malware name
	TargetType int            // 0=any, 1=PE, 2=OLE2, 3=HTML, 4=Mail, 5=Graphics, 6=ELF, 7=ASCII, 9=MachO
	Offset     string         // Raw offset string: "*", "n", "EOF-n", "EP+n", etc.
	RawHex     string         // Original hex pattern string for debugging
	Pattern    *regexp.Regexp // Compiled regex from hex pattern (for complex patterns)
	FixedBytes []byte         // Direct byte pattern for simple fixed-hex signatures (no wildcards)
	IsFixed    bool           // True if the pattern is a simple fixed-byte pattern (no wildcards)
}

// NDBStore holds all loaded NDB body signatures.
type NDBStore struct {
	Signatures []*NDBSignature
}

// NewNDBStore creates a new empty NDBStore.
func NewNDBStore() *NDBStore {
	return &NDBStore{
		Signatures: make([]*NDBSignature, 0, 1024),
	}
}

// TotalCount returns the number of loaded NDB signatures.
func (s *NDBStore) TotalCount() int {
	return len(s.Signatures)
}

// LoadNDB parses body signatures from a reader (content of .ndb file).
// Format: MalwareName:TargetType:Offset:HexSignature[:MinFL[:MaxFL]]
func (s *NDBStore) LoadNDB(r io.Reader, sourceName string) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	lineNum := 0
	loaded := 0
	skipped := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		// Split into at least 4 fields: Name:TargetType:Offset:HexSig[:MinFL[:MaxFL]]
		parts := strings.SplitN(line, ":", 6)
		if len(parts) < 4 {
			slog.Debug("Invalid NDB signature format, skipping", "source", sourceName, "line", lineNum)
			skipped++
			continue
		}

		name := strings.TrimSpace(parts[0])
		targetTypeStr := strings.TrimSpace(parts[1])
		offset := strings.TrimSpace(parts[2])
		hexSig := strings.TrimSpace(parts[3])

		if len(name) == 0 || len(hexSig) == 0 {
			skipped++
			continue
		}

		targetType, err := strconv.Atoi(targetTypeStr)
		if err != nil {
			slog.Debug("Invalid target type in NDB signature, skipping", "source", sourceName, "line", lineNum, "target_type", targetTypeStr)
			skipped++
			continue
		}

		sig, err := compileNDBSignature(name, targetType, offset, hexSig)
		if err != nil {
			slog.Debug("Failed to compile NDB signature, skipping", "source", sourceName, "line", lineNum, "name", name, "error", err)
			skipped++
			continue
		}

		s.Signatures = append(s.Signatures, sig)
		loaded++
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading NDB signatures from %s: %w", sourceName, err)
	}

	slog.Info("Loaded ClamAV NDB signatures",
		"source", sourceName,
		"loaded", loaded,
		"skipped", skipped)

	return nil
}

// Match checks the given content against all loaded NDB signatures and returns
// the names of any matching signatures. The fileSize is used for EOF-based offsets.
//
// TargetType enforcement: each signature carries a ClamAV target type (e.g. 1=PE,
// 6=ELF). This method detects the actual file type from content magic bytes and
// skips any signature whose TargetType does not match, preventing Windows-targeted
// signatures (Win.Trojan.*) from firing on Linux ELF binaries.
func (s *NDBStore) Match(content []byte, fileSize int64) []string {
	var matches []string

	// Detect the file type once for the entire content buffer so that every
	// signature can be filtered without re-reading magic bytes in the loop.
	detectedType := detectFileType(content)

	for _, sig := range s.Signatures {
		// --- TargetType filter ---
		// A signature with TargetType == NDBTargetAny (0) matches all files.
		if sig.TargetType != NDBTargetAny {
			if detectedType != NDBTargetAny {
				// We detected a specific file type. The signature MUST match it.
				if sig.TargetType != detectedType {
					continue
				}
			} else {
				// We couldn't detect the file type (it's generic, like a .pb or .txt).
				// However, if the signature expects a format we CAN robustly detect
				// (PE, ELF, Mach-O, OLE2), we can safely skip the signature, because
				// if the file actually were that format, we would have detected it.
				if sig.TargetType == NDBTargetPE ||
					sig.TargetType == NDBTargetELF ||
					sig.TargetType == NDBTargetMachO ||
					sig.TargetType == NDBTargetOLE2 {
					continue
				}
			}
		}

		// Determine the slice of content to search based on offset
		searchContent := resolveOffsetContent(content, sig.Offset, fileSize)
		if searchContent == nil {
			continue
		}

		if sig.IsFixed {
			// Fast path: direct byte comparison
			if bytes.Contains(searchContent, sig.FixedBytes) {
				matches = append(matches, sig.Name)
			}
		} else if sig.Pattern != nil {
			// Regex path: match compiled pattern against content
			if sig.Pattern.Match(searchContent) {
				matches = append(matches, sig.Name)
			}
		}
	}

	return matches
}

// resolveOffsetContent returns the subset of content to search based on the ClamAV offset spec.
func resolveOffsetContent(content []byte, offset string, fileSize int64) []byte {
	if len(content) == 0 {
		return nil
	}

	// "*" means search entire content
	if offset == "*" || offset == "" {
		return content
	}

	// Handle floating offset: "n,maxshift" → search from n to n+maxshift
	if idx := strings.IndexByte(offset, ','); idx >= 0 {
		baseStr := offset[:idx]
		shiftStr := offset[idx+1:]

		base, err := strconv.ParseInt(baseStr, 10, 64)
		if err != nil || base < 0 {
			return content
		}

		maxShift, err := strconv.ParseInt(shiftStr, 10, 64)
		if err != nil || maxShift < 0 {
			maxShift = 0
		}

		start := base
		end := base + maxShift + 256

		if start >= int64(len(content)) {
			return nil
		}

		if end > int64(len(content)) {
			end = int64(len(content))
		}

		return content[start:end]
	}

	// Handle "EOF-n" offset
	if strings.HasPrefix(offset, "EOF-") {
		nStr := offset[4:]

		n, err := strconv.ParseInt(nStr, 10, 64)
		if err != nil || n < 0 {
			return content
		}

		start := int64(len(content)) - n
		if start < 0 {
			start = 0
		}

		return content[start:]
	}

	// Handle PE/ELF specific offsets — skip for now as we don't parse those structures.
	// EP+n, EP-n, Sx+n, SEx, SL+n are all PE/ELF specific.
	if strings.HasPrefix(offset, "EP") || strings.HasPrefix(offset, "S") {
		// Fall back to full content search for PE/ELF offsets
		return content
	}

	// Handle plain numeric offset
	n, err := strconv.ParseInt(offset, 10, 64)
	if err != nil {
		return content
	}

	if n >= int64(len(content)) {
		return nil
	}

	return content[n:]
}

// compileNDBSignature compiles a ClamAV hex pattern string into a NDBSignature.
func compileNDBSignature(name string, targetType int, offset, hexSig string) (*NDBSignature, error) {
	sig := &NDBSignature{
		Name:       name,
		TargetType: targetType,
		Offset:     offset,
		RawHex:     hexSig,
	}

	// Check if this is a simple fixed hex pattern (no wildcards or special chars)
	if isSimpleHexPattern(hexSig) {
		decoded, err := hex.DecodeString(hexSig)
		if err != nil {
			return nil, fmt.Errorf("failed to decode simple hex pattern: %w", err)
		}

		sig.FixedBytes = decoded
		sig.IsFixed = true

		return sig, nil
	}

	// Complex pattern: compile to regex
	regexStr, err := clamHexToRegex(hexSig)
	if err != nil {
		return nil, fmt.Errorf("failed to convert hex pattern to regex: %w", err)
	}

	compiled, err := regexp.Compile(regexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex from hex pattern: %w", err)
	}

	sig.Pattern = compiled
	return sig, nil
}

// isSimpleHexPattern returns true if the hex signature contains no wildcards or
// special ClamAV operators — just plain hex characters.
func isSimpleHexPattern(hexSig string) bool {
	for _, c := range hexSig {
		if !isHexChar(byte(c)) {
			return false
		}
	}

	// Must also be even length for valid hex
	return len(hexSig) > 0 && len(hexSig)%2 == 0
}

// isHexChar returns true if c is a valid hexadecimal character.
func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// clamHexToRegex converts a ClamAV hex signature pattern to a Go regex pattern
// that operates on raw bytes.
func clamHexToRegex(hexSig string) (string, error) {
	var result strings.Builder
	i := 0

	for i < len(hexSig) {
		c := hexSig[i]

		switch {
		// Handle alternates: (aa|bb|cc)
		case c == '(':
			endIdx := strings.IndexByte(hexSig[i:], ')')
			if endIdx < 0 {
				return "", fmt.Errorf("unmatched '(' in hex pattern at position %d", i)
			}

			altContent := hexSig[i+1 : i+endIdx]

			altRegex, err := compileAlternates(altContent)
			if err != nil {
				return "", fmt.Errorf("failed to compile alternates at position %d: %w", i, err)
			}

			result.WriteString(altRegex)
			i += endIdx + 1

		// Handle byte-count ranges: {n}, {n-m}, {-n}, {n-}
		case c == '{':
			endIdx := strings.IndexByte(hexSig[i:], '}')
			if endIdx < 0 {
				return "", fmt.Errorf("unmatched '{' in hex pattern at position %d", i)
			}

			rangeContent := hexSig[i+1 : i+endIdx]
			rangeRegex, err := compileByteRange(rangeContent)
			if err != nil {
				return "", fmt.Errorf("failed to compile byte range at position %d: %w", i, err)
			}

			result.WriteString(rangeRegex)
			i += endIdx + 1

		// Handle wildcard star: any number of bytes
		case c == '*':
			result.WriteString("[\\x00-\\xff]*?")
			i++

		// Handle byte pairs (including ?? and nibble wildcards)
		case isHexChar(c) || c == '?':
			if i+1 >= len(hexSig) {
				return "", fmt.Errorf("incomplete byte at position %d", i)
			}
			high := hexSig[i]
			low := hexSig[i+1]

			if high == '?' && low == '?' {
				// ?? → any single byte
				result.WriteString("[\\x00-\\xff]")
			} else if high == '?' {
				// ?a → low nibble match
				lowVal, ok := hexDigitValue(low)
				if !ok {
					return "", fmt.Errorf("invalid hex char '%c' at position %d", low, i+1)
				}

				writeLowNibbleClass(&result, lowVal)
			} else if low == '?' {
				// a? → high nibble match
				highVal, ok := hexDigitValue(high)
				if !ok {
					return "", fmt.Errorf("invalid hex char '%c' at position %d", high, i)
				}

				writeHighNibbleClass(&result, highVal)
			} else {
				// Normal hex byte pair
				if !isHexChar(high) || !isHexChar(low) {
					return "", fmt.Errorf("invalid hex chars '%c%c' at position %d", high, low, i)
				}

				byteVal, err := strconv.ParseUint(string([]byte{high, low}), 16, 8)
				if err != nil {
					return "", fmt.Errorf("failed to parse hex byte at position %d: %w", i, err)
				}

				result.WriteString(fmt.Sprintf("\\x%02x", byteVal))
			}
			i += 2

		// Handle '!' (negation) — skip for now, rare in signatures
		case c == '!':
			// Negation prefix for alternates, advance to next char
			i++

		default:
			return "", fmt.Errorf("unexpected character '%c' at position %d", c, i)
		}
	}

	return result.String(), nil
}

// compileAlternates converts a ClamAV alternate expression like "aa|bb|cc" into
// a regex alternation group operating on raw bytes.
func compileAlternates(content string) (string, error) {
	alts := strings.Split(content, "|")
	if len(alts) == 0 {
		return "", fmt.Errorf("empty alternation group")
	}

	var parts []string
	for _, alt := range alts {
		alt = strings.TrimSpace(alt)
		if len(alt) == 0 {
			continue
		}

		// Each alternate can itself be a hex pattern (possibly with wildcards)
		if isSimpleHexPattern(alt) {
			// Simple hex bytes
			decoded, err := hex.DecodeString(alt)
			if err != nil {
				return "", fmt.Errorf("failed to decode alternate hex '%s': %w", alt, err)
			}

			var buf strings.Builder
			for _, b := range decoded {
				buf.WriteString(fmt.Sprintf("\\x%02x", b))
			}

			parts = append(parts, buf.String())
		} else {
			// Complex alternate with wildcards — recursively convert
			subRegex, err := clamHexToRegex(alt)
			if err != nil {
				return "", fmt.Errorf("failed to compile alternate pattern '%s': %w", alt, err)
			}

			parts = append(parts, subRegex)
		}
	}

	if len(parts) == 0 {
		return "", fmt.Errorf("no valid alternates found")
	}

	return "(?:" + strings.Join(parts, "|") + ")", nil
}

// compileByteRange converts a ClamAV byte-count range specifier to a regex quantifier.
// Supported formats: {n}, {-n}, {n-}, {n-m}
func compileByteRange(content string) (string, error) {
	content = strings.TrimSpace(content)

	if strings.HasPrefix(content, "-") {
		// {-n}: 0 to n bytes
		nStr := content[1:]

		n, err := strconv.Atoi(nStr)
		if err != nil {
			return "", fmt.Errorf("invalid range upper bound '%s': %w", nStr, err)
		}

		return fmt.Sprintf("[\\x00-\\xff]{0,%d}", n), nil
	}

	if strings.HasSuffix(content, "-") {
		// {n-}: n or more bytes (capped at n+4096 to avoid catastrophic backtracking)
		nStr := content[:len(content)-1]

		n, err := strconv.Atoi(nStr)
		if err != nil {
			return "", fmt.Errorf("invalid range lower bound '%s': %w", nStr, err)
		}

		maxCap := n + 4096

		return fmt.Sprintf("[\\x00-\\xff]{%d,%d}", n, maxCap), nil
	}

	if dashIdx := strings.IndexByte(content, '-'); dashIdx >= 0 {
		// {n-m}: n to m bytes
		nStr := content[:dashIdx]
		mStr := content[dashIdx+1:]

		n, err := strconv.Atoi(nStr)
		if err != nil {
			return "", fmt.Errorf("invalid range lower bound '%s': %w", nStr, err)
		}

		m, err := strconv.Atoi(mStr)
		if err != nil {
			return "", fmt.Errorf("invalid range upper bound '%s': %w", mStr, err)
		}

		if m < n {
			return "", fmt.Errorf("invalid range: upper bound %d < lower bound %d", m, n)
		}

		return fmt.Sprintf("[\\x00-\\xff]{%d,%d}", n, m), nil
	}

	// {n}: exactly n bytes
	n, err := strconv.Atoi(content)
	if err != nil {
		return "", fmt.Errorf("invalid byte count '%s': %w", content, err)
	}

	return fmt.Sprintf("[\\x00-\\xff]{%d}", n), nil
}

// hexDigitValue converts a hex character to its numeric value (0-15).
func hexDigitValue(c byte) (byte, bool) {
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

// writeHighNibbleClass writes a regex character class matching all bytes
// with the given high nibble value.
func writeHighNibbleClass(w *strings.Builder, highNibble byte) {
	low := highNibble << 4
	high := (highNibble << 4) | 15

	w.WriteString(fmt.Sprintf("[\\x%02x-\\x%02x]", low, high))
}

// writeLowNibbleClass writes a regex character class matching all bytes
// with the given low nibble value.
func writeLowNibbleClass(w *strings.Builder, lowNibble byte) {
	w.WriteString("(?:")

	first := true
	for h := byte(0); h < 16; h++ {
		byteVal := (h << 4) | lowNibble
		if !first {
			w.WriteString("|")
		}

		w.WriteString(fmt.Sprintf("\\x%02x", byteVal))
		first = false
	}

	w.WriteString(")")
}
