package clamav

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
)

// MDBEntry represents a single PE section hash signature from .mdb/.msb files.
type MDBEntry struct {
	Name        string // Malware name
	SectionSize int64  // Expected PE section size
}

// MDBStore holds all loaded PE section hash signatures from .mdb and .msb files.
// These signatures match against individual PE sections rather than entire files.
type MDBStore struct {
	MD5Hashes    map[string]MDBEntry // MD5Hashes maps PE section MD5 hashes to their entries.
	SHA1Hashes   map[string]MDBEntry // SHA1Hashes maps PE section SHA1 hashes to their entries.
	SHA256Hashes map[string]MDBEntry // SHA256Hashes maps PE section SHA256 hashes to their entries.
}

// NewMDBStore creates a new empty MDBStore.
func NewMDBStore() *MDBStore {
	return &MDBStore{
		MD5Hashes:    make(map[string]MDBEntry),
		SHA1Hashes:   make(map[string]MDBEntry),
		SHA256Hashes: make(map[string]MDBEntry),
	}
}

// TotalCount returns the total number of MDB signatures loaded across all types.
func (s *MDBStore) TotalCount() int {
	return len(s.MD5Hashes) + len(s.SHA1Hashes) + len(s.SHA256Hashes)
}

// LoadMDB parses PE section hash signatures from a reader (content of .mdb or .msb file).
// Format: PESectionSize:PESectionHash:MalwareName
// Note: The order is reversed compared to HDB (size comes first, then hash).
// Hash type is auto-detected by length: MD5=32, SHA1=40, SHA256=64.
func (s *MDBStore) LoadMDB(r io.Reader, sourceName string) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	loaded := 0
	skipped := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if len(line) == 0 || line[0] == '#' {
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			slog.Debug("Invalid MDB signature format, skipping", "source", sourceName, "line", lineNum)
			skipped++
			continue
		}

		sizeStr := strings.TrimSpace(parts[0])
		hashStr := strings.ToLower(strings.TrimSpace(parts[1]))
		name := strings.TrimSpace(parts[2])

		if len(name) == 0 {
			slog.Debug("Empty malware name in MDB signature, skipping", "source", sourceName, "line", lineNum)
			skipped++
			continue
		}

		sectionSize, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil {
			slog.Debug("Invalid section size in MDB signature, skipping", "source", sourceName, "line", lineNum, "size", sizeStr)
			skipped++
			continue
		}

		entry := MDBEntry{
			Name:        name,
			SectionSize: sectionSize,
		}

		// Auto-detect hash type by length
		switch len(hashStr) {
		case 32: // MD5
			s.MD5Hashes[hashStr] = entry
			loaded++

		case 40: // SHA1
			s.SHA1Hashes[hashStr] = entry
			loaded++

		case 64: // SHA256
			s.SHA256Hashes[hashStr] = entry
			loaded++

		default:
			slog.Debug("Unknown hash length in MDB signature, skipping", "source", sourceName, "line", lineNum, "hash_len", len(hashStr))
			skipped++
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading MDB signatures from %s: %w", sourceName, err)
	}

	slog.Info("Loaded ClamAV MDB/MSB signatures",
		"source", sourceName,
		"loaded", loaded,
		"skipped", skipped)

	return nil
}
