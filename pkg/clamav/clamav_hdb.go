package clamav

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
)

// HashEntry represents a single hash-based ClamAV signature entry.
type HashEntry struct {
	Name     string // Malware name
	FileSize int64  // Expected file size, -1 means wildcard (any size)
}

// HDBStore holds all loaded hash signatures from .hdb and .hsb files,
// organized by hash algorithm type for efficient lookup.
type HDBStore struct {
	MD5Hashes    map[string]HashEntry // 32-char hex MD5 → entry
	SHA1Hashes   map[string]HashEntry // 40-char hex SHA1 → entry
	SHA256Hashes map[string]HashEntry // 64-char hex SHA256 → entry
}

// NewHDBStore creates a new empty HDBStore.
func NewHDBStore() *HDBStore {
	return &HDBStore{
		MD5Hashes:    make(map[string]HashEntry),
		SHA1Hashes:   make(map[string]HashEntry),
		SHA256Hashes: make(map[string]HashEntry),
	}
}

// TotalCount returns the total number of hash signatures loaded across all types.
func (s *HDBStore) TotalCount() int {
	return len(s.MD5Hashes) + len(s.SHA1Hashes) + len(s.SHA256Hashes)
}

// LoadHDB parses hash signatures from a reader (content of .hdb or .hsb file).
// Format: HashString:FileSize:MalwareName
// Hash type is auto-detected by length: MD5=32, SHA1=40, SHA256=64.
func (s *HDBStore) LoadHDB(r io.Reader, sourceName string) error {
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
			slog.Debug("Invalid HDB signature format, skipping", "source", sourceName, "line", lineNum)
			skipped++
			continue
		}

		hashStr := strings.ToLower(strings.TrimSpace(parts[0]))
		sizeStr := strings.TrimSpace(parts[1])
		name := strings.TrimSpace(parts[2])

		if len(name) == 0 {
			slog.Debug("Empty malware name in HDB signature, skipping", "source", sourceName, "line", lineNum)
			skipped++
			continue
		}

		// Parse file size; "*" means any size
		var fileSize int64 = -1
		if sizeStr != "*" && sizeStr != "" {
			var err error
			fileSize, err = strconv.ParseInt(sizeStr, 10, 64)
			if err != nil {
				slog.Debug("Invalid file size in HDB signature, skipping", "source", sourceName, "line", lineNum, "size", sizeStr)
				skipped++
				continue
			}
		}

		entry := HashEntry{
			Name:     name,
			FileSize: fileSize,
		}

		// Auto-detect hash type by length and store in the appropriate map
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
			slog.Debug("Unknown hash length in HDB signature, skipping", "source", sourceName, "line", lineNum, "hash_len", len(hashStr))
			skipped++
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading HDB signatures from %s: %w", sourceName, err)
	}

	slog.Info("Loaded ClamAV HDB/HSB signatures",
		"source", sourceName,
		"loaded", loaded,
		"skipped", skipped,
		"md5_count", len(s.MD5Hashes),
		"sha1_count", len(s.SHA1Hashes),
		"sha256_count", len(s.SHA256Hashes))

	return nil
}

// LookupMD5 checks if the given MD5 hash matches a known signature.
// Returns the HashEntry and true if found, zero-value and false otherwise.
func (s *HDBStore) LookupMD5(hash string, fileSize int64) (HashEntry, bool) {
	entry, ok := s.MD5Hashes[strings.ToLower(hash)]
	if !ok {
		return HashEntry{}, false
	}

	// Check file size if the signature specifies one
	if entry.FileSize >= 0 && entry.FileSize != fileSize {
		return HashEntry{}, false
	}

	return entry, true
}

// LookupSHA1 checks if the given SHA1 hash matches a known signature.
func (s *HDBStore) LookupSHA1(hash string, fileSize int64) (HashEntry, bool) {
	entry, ok := s.SHA1Hashes[strings.ToLower(hash)]
	if !ok {
		return HashEntry{}, false
	}

	if entry.FileSize >= 0 && entry.FileSize != fileSize {
		return HashEntry{}, false
	}

	return entry, true
}

// LookupSHA256 checks if the given SHA256 hash matches a known signature.
func (s *HDBStore) LookupSHA256(hash string, fileSize int64) (HashEntry, bool) {
	entry, ok := s.SHA256Hashes[strings.ToLower(hash)]
	if !ok {
		return HashEntry{}, false
	}

	if entry.FileSize >= 0 && entry.FileSize != fileSize {
		return HashEntry{}, false
	}

	return entry, true
}
