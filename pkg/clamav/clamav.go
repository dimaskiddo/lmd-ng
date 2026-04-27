package clamav

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CVDHeader represents the parsed metadata from a ClamAV .cvd or .cld file header.
type CVDHeader struct {
	Magic        string // Should be "ClamAV-VDB"
	BuildTime    string // Build timestamp string
	Version      int    // Database version number
	NumSigs      int    // Total number of signatures
	FLevel       int    // Minimum functionality level required
	MD5Sum       string // MD5 checksum of the database payload
	DSig         string // Digital signature
	Builder      string // Builder name
	BuildTimeSec int64  // Build time in seconds (epoch)
}

// ClamAVSignatureDB represents the complete in-memory database of ClamAV signatures
// loaded from one or more CVD/CLD files or flat signature files.
type ClamAVSignatureDB struct {
	HDB *HDBStore // File hash signatures (.hdb, .hsb)
	MDB *MDBStore // PE section hash signatures (.mdb, .msb)
	NDB *NDBStore // Body/extended signatures (.ndb)
}

// NewClamAVSignatureDB creates a new empty ClamAVSignatureDB.
func NewClamAVSignatureDB() *ClamAVSignatureDB {
	return &ClamAVSignatureDB{
		HDB: NewHDBStore(),
		MDB: NewMDBStore(),
		NDB: NewNDBStore(),
	}
}

// TotalSignatures returns the total number of signatures loaded across all types.
func (db *ClamAVSignatureDB) TotalSignatures() int {
	return db.HDB.TotalCount() + db.MDB.TotalCount() + db.NDB.TotalCount()
}

// LoadFromDirectory loads all ClamAV signature databases from the given directory.
// It searches for .cvd, .cld, and flat signature files (.hdb, .hsb, .ndb, .mdb, .msb).
func LoadFromDirectory(clamAVDir string) (*ClamAVSignatureDB, error) {
	db := NewClamAVSignatureDB()

	if _, err := os.Stat(clamAVDir); os.IsNotExist(err) {
		return nil, fmt.Errorf("ClamAV database directory does not exist: %s", clamAVDir)
	}

	// First, try to load CVD files (compressed containers)
	cvdFiles := []string{"main.cvd", "daily.cvd", "bytecode.cvd"}
	for _, cvdName := range cvdFiles {
		cvdPath := filepath.Join(clamAVDir, cvdName)
		if _, err := os.Stat(cvdPath); err == nil {
			slog.Info("Loading ClamAV CVD file", "path", cvdPath)

			if err := db.loadCVD(cvdPath); err != nil {
				slog.Warn("Failed to load CVD file, skipping", "path", cvdPath, "error", err)
			}
		}
	}

	// Then, try CLD files (may be uncompressed or repackaged)
	cldFiles := []string{"main.cld", "daily.cld", "bytecode.cld"}
	for _, cldName := range cldFiles {
		cldPath := filepath.Join(clamAVDir, cldName)
		if _, err := os.Stat(cldPath); err == nil {
			slog.Info("Loading ClamAV CLD file", "path", cldPath)

			if err := db.loadCVD(cldPath); err != nil {
				slog.Warn("Failed to load CLD file, skipping", "path", cldPath, "error", err)
			}
		}
	}

	// Also load any flat (unpackaged) signature files directly
	flatExtensions := map[string]string{
		".hdb": "hdb",
		".hsb": "hsb",
		".ndb": "ndb",
		".mdb": "mdb",
		".msb": "msb",
	}

	entries, err := os.ReadDir(clamAVDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read ClamAV directory %s: %w", clamAVDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(entry.Name()))
		sigType, isFlatSig := flatExtensions[ext]
		if !isFlatSig {
			continue
		}

		flatPath := filepath.Join(clamAVDir, entry.Name())
		slog.Info("Loading ClamAV "+strings.ToUpper(sigType)+" signatures file", "path", flatPath, "type", sigType)

		file, err := os.Open(flatPath)
		if err != nil {
			slog.Warn("Failed to open signature file, skipping", "path", flatPath, "error", err)
			continue
		}

		if err := db.loadSignatureReader(file, entry.Name(), sigType); err != nil {
			slog.Warn("Failed to load signature file, skipping", "path", flatPath, "error", err)
		}

		file.Close()
	}

	slog.Info("ClamAV signature database loaded",
		"hdb_total", db.HDB.TotalCount(),
		"mdb_total", db.MDB.TotalCount(),
		"ndb_total", db.NDB.TotalCount(),
		"total_signatures", db.TotalSignatures())

	return db, nil
}

// loadCVD loads signatures from a single .cvd or .cld container file.
// The CVD format: 512-byte text header + tar.gz payload.
func (db *ClamAVSignatureDB) loadCVD(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open CVD/CLD file %s: %w", filePath, err)
	}
	defer file.Close()

	// Read the 512-byte header
	header := make([]byte, 512)
	n, err := io.ReadFull(file, header)
	if err != nil {
		return fmt.Errorf("failed to read CVD header from %s (read %d bytes): %w", filePath, n, err)
	}

	// Parse the header
	cvdHeader, err := parseCVDHeader(string(header))
	if err != nil {
		slog.Warn("Failed to parse CVD header, attempting to extract anyway", "path", filePath, "error", err)
	} else {
		slog.Info("CVD header parsed",
			"path", filePath,
			"version", cvdHeader.Version,
			"sigs", cvdHeader.NumSigs,
			"flevel", cvdHeader.FLevel,
			"builder", cvdHeader.Builder)
	}

	// The rest of the file is a tar.gz archive.
	// Try gzip first (standard CVD); if that fails, try reading as plain tar (some CLD files).
	if err := db.extractAndLoadTarGz(file, filePath); err != nil {
		// Seek back past the header and try as uncompressed tar
		if _, seekErr := file.Seek(512, io.SeekStart); seekErr != nil {
			return fmt.Errorf("failed to seek in CVD file %s: %w", filePath, seekErr)
		}

		if err2 := db.extractAndLoadTar(file, filePath); err2 != nil {
			return fmt.Errorf("failed to extract CVD/CLD file %s (tried gzip and plain tar): gzip error: %v, tar error: %w", filePath, err, err2)
		}
	}

	return nil
}

// extractAndLoadTarGz decompresses a gzip-compressed tar archive and loads all
// recognized signature files from it into memory.
func (db *ClamAVSignatureDB) extractAndLoadTarGz(r io.Reader, sourcePath string) error {
	gzReader, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	return db.extractAndLoadTar(gzReader, sourcePath)
}

// extractAndLoadTar reads a tar archive and loads all recognized signature files.
func (db *ClamAVSignatureDB) extractAndLoadTar(r io.Reader, sourcePath string) error {
	tarReader := tar.NewReader(r)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("error reading tar entry from %s: %w", sourcePath, err)
		}

		// Only process regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		name := filepath.Base(header.Name)
		ext := strings.ToLower(filepath.Ext(name))

		// Determine signature type by extension
		var sigType string
		switch ext {
		case ".hdb", ".hsb":
			sigType = "hdb"

		case ".ndb":
			sigType = "ndb"

		case ".mdb", ".msb":
			sigType = "mdb"

		default:
			// Skip unsupported file types (e.g., .ldb, .fp, .info, .cfg)
			slog.Debug("Skipping unsupported signature file in CVD archive", "file", name, "ext", ext, "cvd", sourcePath)
			continue
		}

		// Read the file content into a memory buffer
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, tarReader); err != nil {
			slog.Warn("Failed to read signature file from CVD archive, skipping", "file", name, "cvd", sourcePath, "error", err)
			continue
		}

		sourceName := fmt.Sprintf("%s:%s", filepath.Base(sourcePath), name)
		if err := db.loadSignatureReader(&buf, sourceName, sigType); err != nil {
			slog.Warn("Failed to load signature file from CVD archive, skipping", "file", name, "cvd", sourcePath, "error", err)
		}
	}

	return nil
}

// loadSignatureReader dispatches signature loading to the appropriate store
// based on the signature type.
func (db *ClamAVSignatureDB) loadSignatureReader(r io.Reader, sourceName, sigType string) error {
	switch sigType {
	case "hdb", "hsb":
		return db.HDB.LoadHDB(r, sourceName)

	case "ndb":
		return db.NDB.LoadNDB(r, sourceName)

	case "mdb", "msb":
		return db.MDB.LoadMDB(r, sourceName)

	default:
		return fmt.Errorf("unknown signature type: %s", sigType)
	}
}

// parseCVDHeader parses the 512-byte CVD header string.
// Format: ClamAV-VDB:buildtime:version:sigs:flevel:md5:dsig:builder:stime
func parseCVDHeader(headerStr string) (*CVDHeader, error) {
	// Trim any trailing null bytes or whitespace
	headerStr = strings.TrimRight(headerStr, "\x00 \n\r\t")

	parts := strings.Split(headerStr, ":")
	if len(parts) < 8 {
		return nil, fmt.Errorf("invalid CVD header: expected at least 8 colon-separated fields, got %d", len(parts))
	}

	if parts[0] != "ClamAV-VDB" {
		return nil, fmt.Errorf("invalid CVD magic: expected 'ClamAV-VDB', got '%s'", parts[0])
	}

	header := &CVDHeader{
		Magic:     parts[0],
		BuildTime: parts[1],
		MD5Sum:    parts[5],
		DSig:      parts[6],
		Builder:   parts[7],
	}

	// Parse numeric fields, tolerating parse errors
	if v, err := strconv.Atoi(strings.TrimSpace(parts[2])); err == nil {
		header.Version = v
	}

	if v, err := strconv.Atoi(strings.TrimSpace(parts[3])); err == nil {
		header.NumSigs = v
	}

	if v, err := strconv.Atoi(strings.TrimSpace(parts[4])); err == nil {
		header.FLevel = v
	}

	if len(parts) > 8 {
		if v, err := strconv.ParseInt(strings.TrimSpace(parts[8]), 10, 64); err == nil {
			header.BuildTimeSec = v
		}
	}

	return header, nil
}
