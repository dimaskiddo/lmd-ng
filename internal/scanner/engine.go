package scanner

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dimaskiddo/lmd-ng/pkg/clamav"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// ScanResult represents a single detected malware match within a file.
type ScanResult struct {
	SignatureName string // The name of the matching signature
	SignatureType string // The type of signature (e.g., "MD5", "HEX", "YARA")
	FilePath      string // The path to the file where the match was found
	Offset        int64  // The offset within the file where the match occurred (if applicable)
	DetectionID   string // A unique ID for this detection event
}

// SignatureEngine defines the contract for malware signature matching engines.
type SignatureEngine interface {
	// Scan processes the provided reader and returns all detected malware matches.
	// It should not close the reader. The reader might be a limited view of the file.
	Scan(ctx context.Context, r io.Reader, filePath string) ([]*ScanResult, error)
	// Name returns the name of the signature engine.
	Name() string
}

// LMDSignatureScanner implements the SignatureEngine interface for LMD native signatures.
type LMDSignatureScanner struct {
	cfg           *config.Config
	md5Scanner    *md5Scanner
	sha256Scanner *sha256Scanner
	hexScanner    *hexScanner
	clamavScanner *clamav.ClamAVSignatureDB
}

// NewLMDSignatureScanner creates a new LMD native signature scanner.
func NewLMDSignatureScanner(cfg *config.Config) (*LMDSignatureScanner, error) {
	md5S, err := NewMD5Scanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create MD5 scanner: %w", err)
	}

	sha256S, err := NewSHA256Scanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SHA256 scanner: %w", err)
	}

	hexS, err := NewHexScanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HEX scanner: %w", err)
	}

	rfxnPath := filepath.Join(cfg.App.SignaturesDir, "rfxn")
	clamavS, err := clamav.LoadFromDirectory(rfxnPath)
	if err != nil {
		// Log warning rather than erroring out if rfxn directory doesn't exist yet
		log.Debug("Failed to load RFXN ClamAV signatures", "error", err)
	}

	return &LMDSignatureScanner{
		cfg:           cfg,
		md5Scanner:    md5S,
		sha256Scanner: sha256S,
		hexScanner:    hexS,
		clamavScanner: clamavS,
	}, nil
}

// Scan implements the SignatureEngine interface for LMDSignatureScanner.
func (s *LMDSignatureScanner) Scan(ctx context.Context, r io.Reader, filePath string) ([]*ScanResult, error) {
	var dataReader *bytes.Reader

	file, ok := r.(*os.File)
	if !ok {
		log.Warn("Scanner received non-seekable reader, falling back to memory read for efficiency compromises.", "filepath", filePath)

		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read all data from non-seekable reader: %w", err)
		}

		dataReader = bytes.NewReader(data)
		r = dataReader

		file = nil
	}

	// --- Hash Scanning (MD5 + SHA256) ---
	md5Hasher := md5.New()
	sha256Hasher := sha256.New()
	multiWriter := io.MultiWriter(md5Hasher, sha256Hasher)

	if file != nil {
		_, err := file.Seek(0, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to seek file to start for hash: %w", err)
		}
	} else if dataReader != nil {
		_, err := dataReader.Seek(0, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to seek memory reader to start for hash: %w", err)
		}
	}

	_, err := io.Copy(multiWriter, r)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to calculate hash: %w", err)
	}

	md5Hash := hex.EncodeToString(md5Hasher.Sum(nil))
	sha256Hash := hex.EncodeToString(sha256Hasher.Sum(nil))

	if sigName := s.md5Scanner.Check(md5Hash); sigName != "" {
		return []*ScanResult{{
			SignatureName: sigName,
			SignatureType: "MD5",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("md5.%s", md5Hash),
		}}, nil
	}

	if sigName := s.sha256Scanner.Check(sha256Hash); sigName != "" {
		return []*ScanResult{{
			SignatureName: sigName,
			SignatureType: "SHA256",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("sha256.%s", sha256Hash),
		}}, nil
	}

	// --- Native ClamAV Scanning for RFXN ---
	if s.clamavScanner != nil && s.clamavScanner.TotalSignatures() > 0 {
		var fileSize int64 = -1
		if file != nil {
			info, err := file.Stat()
			if err == nil {
				fileSize = info.Size()
			}
		} else if dataReader != nil {
			fileSize = int64(dataReader.Len())
		}

		if entry, found := s.clamavScanner.HDB.LookupMD5(md5Hash, fileSize); found {
			return []*ScanResult{{
				SignatureName: entry.Name,
				SignatureType: "RFXN-MD5",
				FilePath:      filePath,
				DetectionID:   fmt.Sprintf("rfxn.md5.%s", md5Hash),
			}}, nil
		}

		if entry, found := s.clamavScanner.HDB.LookupSHA256(sha256Hash, fileSize); found {
			return []*ScanResult{{
				SignatureName: entry.Name,
				SignatureType: "RFXN-SHA256",
				FilePath:      filePath,
				DetectionID:   fmt.Sprintf("rfxn.sha256.%s", sha256Hash),
			}}, nil
		}

		if s.clamavScanner.NDB.TotalCount() > 0 {
			if file != nil {
				_, err := file.Seek(0, io.SeekStart)
				if err != nil {
					return nil, fmt.Errorf("failed to seek file to start for RFXN NDB scan: %w", err)
				}
			} else if dataReader != nil {
				_, err := dataReader.Seek(0, io.SeekStart)
				if err != nil {
					return nil, fmt.Errorf("failed to seek memory reader to start for RFXN NDB scan: %w", err)
				}
			}

			var ndbReader io.Reader = r
			if file != nil {
				ndbReader = file
			} else if dataReader != nil {
				ndbReader = dataReader
			}

			// Read content up to configured hex depth for body pattern matching
			hexDepth := int64(s.cfg.Scanner.HexDepth)
			if hexDepth <= 0 {
				hexDepth = 65536
			}

			limitedReader := io.LimitReader(ndbReader, hexDepth)
			content, err := io.ReadAll(limitedReader)
			if err != nil && err != io.EOF {
				return nil, fmt.Errorf("failed to read content for RFXN NDB scan: %w", err)
			}

			ndbMatches := s.clamavScanner.NDB.Match(content, fileSize)
			if len(ndbMatches) > 0 {
				// Return only the first NDB match
				return []*ScanResult{{
					SignatureName: ndbMatches[0],
					SignatureType: "RFXN-NDB",
					FilePath:      filePath,
					DetectionID:   fmt.Sprintf("rfxn.ndb.%s", ndbMatches[0]),
				}}, nil
			}
		}
	}

	// --- HEX Scanning ---
	var hexReadCloser io.ReadCloser
	if file != nil {
		_, err := file.Seek(0, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to seek file to start for HEX scan: %w", err)
		}

		hexReadCloser = io.NopCloser(io.LimitReader(file, int64(s.cfg.Scanner.HexDepth)))
	} else if dataReader != nil {
		_, err := dataReader.Seek(0, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to seek memory reader to start for HEX scan: %w", err)
		}

		hexReadCloser = io.NopCloser(io.LimitReader(dataReader, int64(s.cfg.Scanner.HexDepth)))
	}

	hexContent, err := io.ReadAll(hexReadCloser)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("failed to read content for HEX scan: %w", err)
	}

	hexMatches := s.hexScanner.Check(hexContent)
	if len(hexMatches) > 0 {
		// Return only the first HEX match
		return []*ScanResult{{
			SignatureName: hexMatches[0],
			SignatureType: "HEX",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("hex.%s", hexMatches[0]),
		}}, nil
	}

	return nil, nil
}

// Name returns the name of the LMDSignatureScanner.
func (s *LMDSignatureScanner) Name() string {
	return "LMD Native Signature Engine"
}

// ClamAVSignatureEngine implements the SignatureEngine interface using ClamAV
// signature databases (.cvd, .cld, .hdb, .hsb, .ndb) loaded in pure Go.
type ClamAVSignatureEngine struct {
	cfg *config.Config
	db  *clamav.ClamAVSignatureDB
}

// NewClamAVSignatureEngine creates a new ClamAV signature scanner by loading
// all signature databases from the configured ClamAV directory.
func NewClamAVSignatureEngine(cfg *config.Config) (*ClamAVSignatureEngine, error) {
	// Resolve the ClamAV DB path
	clamDBPath := cfg.Scanner.ClamAVDBPath
	if clamDBPath == "" {
		clamDBPath = cfg.App.ClamAVDir
	}

	if !filepath.IsAbs(clamDBPath) {
		clamDBPath = filepath.Join(cfg.App.BasePath, clamDBPath)
	}

	log.Info("Initializing ClamAV signature engine", "db_path", clamDBPath)

	db, err := clamav.LoadFromDirectory(clamDBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load ClamAV signature databases from %s: %w", clamDBPath, err)
	}

	if db.TotalSignatures() == 0 {
		log.Warn("ClamAV signature engine initialized with zero signatures", "db_path", clamDBPath)
	} else {
		log.Info("ClamAV signature engine ready",
			"total_signatures", db.TotalSignatures(),
			"hdb_sigs", db.HDB.TotalCount(),
			"ndb_sigs", db.NDB.TotalCount(),
			"mdb_sigs", db.MDB.TotalCount())
	}

	return &ClamAVSignatureEngine{
		cfg: cfg,
		db:  db,
	}, nil
}

// Scan implements the SignatureEngine interface for ClamAVSignatureEngine.
// It performs two phases:
//  1. Hash-based detection: Computes MD5, SHA1, and SHA256 in a single pass
//     and checks against HDB/HSB signatures.
//  2. Body-based detection: Reads file content up to the configured hex depth
//     and matches against NDB body signatures.
func (s *ClamAVSignatureEngine) Scan(ctx context.Context, r io.Reader, filePath string) ([]*ScanResult, error) {
	var results []*ScanResult

	// Obtain a seekable reader. If r is an *os.File we can seek; otherwise buffer it.
	var dataReader *bytes.Reader
	file, isFile := r.(*os.File)
	if !isFile {
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read data for ClamAV scan: %w", err)
		}

		dataReader = bytes.NewReader(data)
	}

	// Helper to seek to start
	seekToStart := func() error {
		if isFile {
			_, err := file.Seek(0, io.SeekStart)
			return err
		}

		_, err := dataReader.Seek(0, io.SeekStart)
		return err
	}

	// Helper to get reader
	getReader := func() io.Reader {
		if isFile {
			return file
		}

		return dataReader
	}

	// Determine file size for hash lookups
	var fileSize int64 = -1
	if isFile {
		info, err := file.Stat()
		if err == nil {
			fileSize = info.Size()
		}
	} else {
		fileSize = int64(dataReader.Len())
	}

	// --- Phase 1: Hash-based detection (MD5 + SHA1 + SHA256 in one pass) ---
	if err := seekToStart(); err != nil {
		return nil, fmt.Errorf("failed to seek to start for hash computation: %w", err)
	}

	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()
	multiHashWriter := io.MultiWriter(md5Hasher, sha1Hasher, sha256Hasher)

	if _, err := io.Copy(multiHashWriter, getReader()); err != nil {
		return nil, fmt.Errorf("failed to compute file hashes: %w", err)
	}

	md5Hash := hex.EncodeToString(md5Hasher.Sum(nil))
	sha1Hash := hex.EncodeToString(sha1Hasher.Sum(nil))
	sha256Hash := hex.EncodeToString(sha256Hasher.Sum(nil))

	// Check MD5 against HDB
	if entry, found := s.db.HDB.LookupMD5(md5Hash, fileSize); found {
		return []*ScanResult{{
			SignatureName: entry.Name,
			SignatureType: "ClamAV-MD5",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("clamav.md5.%s", md5Hash),
		}}, nil
	}

	// Check SHA1 against HSB
	if entry, found := s.db.HDB.LookupSHA1(sha1Hash, fileSize); found {
		return []*ScanResult{{
			SignatureName: entry.Name,
			SignatureType: "ClamAV-SHA1",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("clamav.sha1.%s", sha1Hash),
		}}, nil
	}

	// Check SHA256 against HSB
	if entry, found := s.db.HDB.LookupSHA256(sha256Hash, fileSize); found {
		return []*ScanResult{{
			SignatureName: entry.Name,
			SignatureType: "ClamAV-SHA256",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("clamav.sha256.%s", sha256Hash),
		}}, nil
	}

	// --- Phase 2: Body/NDB signature matching ---
	if s.db.NDB.TotalCount() > 0 {
		if err := seekToStart(); err != nil {
			return nil, fmt.Errorf("failed to seek to start for NDB scan: %w", err)
		}

		// Read content up to configured hex depth for body pattern matching
		hexDepth := int64(s.cfg.Scanner.ClamAVHexDepth)
		if hexDepth <= 0 {
			hexDepth = 65536 // Default: 64KB
		}

		limitedReader := io.LimitReader(getReader(), hexDepth)
		content, err := io.ReadAll(limitedReader)
		if err != nil {
			return nil, fmt.Errorf("failed to read content for NDB scan: %w", err)
		}

		ndbMatches := s.db.NDB.Match(content, fileSize)
		for _, sigName := range ndbMatches {
			results = append(results, &ScanResult{
				SignatureName: sigName,
				SignatureType: "ClamAV-NDB",
				FilePath:      filePath,
				DetectionID:   fmt.Sprintf("clamav.ndb.%s", sigName),
			})
		}
	}

	return results, nil
}

// Name returns the name of the ClamAV signature engine.
func (s *ClamAVSignatureEngine) Name() string {
	return "ClamAV Signature Engine"
}
