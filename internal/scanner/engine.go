package scanner

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/dimaskiddo/lmd-ng/pkg/clamav"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// ScanResult represents a single detected malware match within a file.
type ScanResult struct {
	SignatureName string // The name of the matching signature
	SignatureType string // The type of signature (e.g., "MD5", "HEX", "YARA")
	FilePath      string // The path to the file where the match was found
	DetectionID   string // A unique ID for this detection event
}

// SignatureEngine defines the contract for malware signature matching engines.
type SignatureEngine interface {
	// Scan processes the provided reader and returns all detected malware matches.
	// It should not close the reader. The reader must be a seekable stream.
	Scan(ctx context.Context, r io.ReadSeeker, filePath string) ([]*ScanResult, error)
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
	md5S, err := newMD5Scanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create MD5 scanner: %w", err)
	}

	sha256S, err := newSHA256Scanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create SHA256 scanner: %w", err)
	}

	hexS, err := newHexScanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create HEX scanner: %w", err)
	}

	rfxnPath := filepath.Join(cfg.App.SignaturesDir, "rfxn")
	clamavS, err := clamav.LoadFromDirectory(rfxnPath)
	if err != nil {
		// Log warning rather than erroring out if rfxn directory doesn't exist yet
		log.Debug("Failed to load RFXN ClamAV signatures", "error", err)
	}

	if clamavS != nil && clamavS.TotalSignatures() > 0 {
		log.Info("RFXN signatures loaded",
			"hdb_total", clamavS.HDB.TotalCount(),
			"ndb_total", clamavS.NDB.TotalCount(),
			"total_signatures", clamavS.TotalSignatures())
	} else {
		log.Debug("No RFXN signatures found", "path", rfxnPath)
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
func (s *LMDSignatureScanner) Scan(ctx context.Context, r io.ReadSeeker, filePath string) ([]*ScanResult, error) {
	// --- Hash Scanning (MD5 + SHA1 + SHA256) ---
	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()
	multiWriter := io.MultiWriter(md5Hasher, sha1Hasher, sha256Hasher)

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek reader to start for hash: %w", err)
	}

	_, err := io.Copy(multiWriter, r)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate hash: %w", err)
	}

	md5Hash := hex.EncodeToString(md5Hasher.Sum(nil))
	sha1Hash := hex.EncodeToString(sha1Hasher.Sum(nil))
	sha256Hash := hex.EncodeToString(sha256Hasher.Sum(nil))

	if sigName := s.md5Scanner.Check(md5Hash, filePath); sigName != "" {
		return []*ScanResult{{
			SignatureName: sigName,
			SignatureType: "MD5",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("md5.%s", md5Hash),
		}}, nil
	}

	if sigName := s.sha256Scanner.Check(sha256Hash, filePath); sigName != "" {
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

		// Attempt to get file size for hash lookups if it's an os.File
		if file, ok := r.(*os.File); ok {
			if info, err := file.Stat(); err == nil {
				fileSize = info.Size()
			}
		} else {
			// For generic ReadSeeker, determine size by seeking
			if size, err := r.Seek(0, io.SeekEnd); err == nil {
				fileSize = size
			}
		}

		if entry, found := s.clamavScanner.HDB.LookupMD5(md5Hash, fileSize); found {
			if s.isPathAllowlisted(filePath) {
				log.Warn("RFXN-MD5 match suppressed by allowlist", "file", filePath, "signature", entry.Name)
			} else {
				return []*ScanResult{{
					SignatureName: entry.Name,
					SignatureType: "RFXN-MD5",
					FilePath:      filePath,
					DetectionID:   fmt.Sprintf("rfxn.md5.%s", md5Hash),
				}}, nil
			}
		}

		if entry, found := s.clamavScanner.HDB.LookupSHA1(sha1Hash, fileSize); found {
			if s.isPathAllowlisted(filePath) {
				log.Warn("RFXN-SHA1 match suppressed by allowlist", "file", filePath, "signature", entry.Name)
			} else {
				return []*ScanResult{{
					SignatureName: entry.Name,
					SignatureType: "RFXN-SHA1",
					FilePath:      filePath,
					DetectionID:   fmt.Sprintf("rfxn.sha1.%s", sha1Hash),
				}}, nil
			}
		}

		if entry, found := s.clamavScanner.HDB.LookupSHA256(sha256Hash, fileSize); found {
			if s.isPathAllowlisted(filePath) {
				log.Warn("RFXN-SHA256 match suppressed by allowlist", "file", filePath, "signature", entry.Name)
			} else {
				return []*ScanResult{{
					SignatureName: entry.Name,
					SignatureType: "RFXN-SHA256",
					FilePath:      filePath,
					DetectionID:   fmt.Sprintf("rfxn.sha256.%s", sha256Hash),
				}}, nil
			}
		}

		if s.clamavScanner.NDB.TotalCount() > 0 {
			if _, err := r.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek reader to start for RFXN NDB scan: %w", err)
			}

			// Read content up to configured hex depth for body pattern matching
			hexDepth := int64(s.cfg.Scanner.HexDepth)
			if hexDepth <= 0 {
				hexDepth = 65536
			}

			limitedReader := io.LimitReader(r, hexDepth)
			content, err := io.ReadAll(limitedReader)
			if err != nil {
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

			// Reuse content buffer for HEX scan — no second read needed
			hexMatches := s.hexScanner.Check(content, filePath)
			if len(hexMatches) > 0 {
				return []*ScanResult{{
					SignatureName: hexMatches[0],
					SignatureType: "HEX",
					FilePath:      filePath,
					DetectionID:   fmt.Sprintf("hex.%s", hexMatches[0]),
				}}, nil
			}
		} else {
			// No NDB signatures — read content for HEX scan only
			if _, err := r.Seek(0, io.SeekStart); err != nil {
				return nil, fmt.Errorf("failed to seek reader to start for HEX scan: %w", err)
			}

			hexDepth := int64(s.cfg.Scanner.HexDepth)
			if hexDepth <= 0 {
				hexDepth = 65536
			}

			limitedReader := io.LimitReader(r, hexDepth)
			content, err := io.ReadAll(limitedReader)
			if err != nil {
				return nil, fmt.Errorf("failed to read content for HEX scan: %w", err)
			}

			hexMatches := s.hexScanner.Check(content, filePath)
			if len(hexMatches) > 0 {
				return []*ScanResult{{
					SignatureName: hexMatches[0],
					SignatureType: "HEX",
					FilePath:      filePath,
					DetectionID:   fmt.Sprintf("hex.%s", hexMatches[0]),
				}}, nil
			}
		}
	}

	return nil, nil
}

// Name returns the name of the LMDSignatureScanner.
func (s *LMDSignatureScanner) Name() string {
	return "LMD Native Signature Engine"
}

// MD5Count returns the number of loaded MD5 hash signatures.
func (s *LMDSignatureScanner) MD5Count() int {
	if s.md5Scanner == nil {
		return 0
	}
	return s.md5Scanner.Count()
}

// SHA256Count returns the number of loaded SHA256 hash signatures.
func (s *LMDSignatureScanner) SHA256Count() int {
	if s.sha256Scanner == nil {
		return 0
	}
	return s.sha256Scanner.Count()
}

// HEXCount returns the number of loaded HEX pattern signatures.
func (s *LMDSignatureScanner) HEXCount() int {
	if s.hexScanner == nil {
		return 0
	}
	return s.hexScanner.Count()
}

// RFXNCount returns the total number of RFXN ClamAV signatures (NDB + HDB + MDB).
func (s *LMDSignatureScanner) RFXNCount() int {
	if s.clamavScanner == nil {
		return 0
	}
	return s.clamavScanner.TotalSignatures()
}

// isPathAllowlisted returns true if filePath starts with any configured
// HashAllowlistPaths prefix. Used to suppress hash-based detections for
// known-good system paths (e.g. /usr/bin, /usr/lib).
func (s *LMDSignatureScanner) isPathAllowlisted(filePath string) bool {
	for _, prefix := range s.cfg.Scanner.HashAllowlistPaths {
		if strings.HasPrefix(filePath, prefix) {
			return true
		}
	}
	return false
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
func (s *ClamAVSignatureEngine) Scan(ctx context.Context, r io.ReadSeeker, filePath string) ([]*ScanResult, error) {
	var results []*ScanResult

	// Determine file size for hash lookups
	var fileSize int64 = -1
	if file, ok := r.(*os.File); ok {
		if info, err := file.Stat(); err == nil {
			fileSize = info.Size()
		}
	} else {
		// Determine size by seeking
		if size, err := r.Seek(0, io.SeekEnd); err == nil {
			fileSize = size
		}
	}

	// --- Phase 1: Hash-based detection (MD5 + SHA1 + SHA256 in one pass) ---
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to start for hash computation: %w", err)
	}

	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()
	multiHashWriter := io.MultiWriter(md5Hasher, sha1Hasher, sha256Hasher)

	if _, err := io.Copy(multiHashWriter, r); err != nil {
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

	// --- Phase 2: PE section hash detection (MDB) ---
	if s.db.MDB.TotalCount() > 0 {
		if _, err := r.Seek(0, io.SeekStart); err == nil {
			// Read first 512 bytes for magic type detection
			magicBuf := make([]byte, 512)
			if n, _ := io.ReadFull(r, magicBuf); n > 0 {
				magicType := detectMagicType(magicBuf[:n])

				if magicType == magicTypePE {
					sections, err := ParsePESections(r)
					if err == nil {
						for _, section := range sections {
							if entry, ok := s.db.MDB.LookupMD5(section.MD5, section.Size); ok {
								return []*ScanResult{{
									SignatureName: entry.Name,
									SignatureType: "ClamAV-MDB",
									FilePath:      filePath,
									DetectionID:   fmt.Sprintf("clamav.mdb.%s.%s", section.Name, section.MD5),
								}}, nil
							}

							if entry, ok := s.db.MDB.LookupSHA1(section.SHA1, section.Size); ok {
								return []*ScanResult{{
									SignatureName: entry.Name,
									SignatureType: "ClamAV-MDB",
									FilePath:      filePath,
									DetectionID:   fmt.Sprintf("clamav.mdb.%s.%s", section.Name, section.SHA1),
								}}, nil
							}

							if entry, ok := s.db.MDB.LookupSHA256(section.SHA256, section.Size); ok {
								return []*ScanResult{{
									SignatureName: entry.Name,
									SignatureType: "ClamAV-MDB",
									FilePath:      filePath,
									DetectionID:   fmt.Sprintf("clamav.mdb.%s.%s", section.Name, section.SHA256),
								}}, nil
							}
						}
					}
				}
			}
		}
	}

	// --- Phase 3: Body/NDB signature matching ---
	if s.db.NDB.TotalCount() > 0 {
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek to start for NDB scan: %w", err)
		}

		// Read content up to configured hex depth for body pattern matching
		hexDepth := int64(s.cfg.Scanner.ClamAVHexDepth)
		if hexDepth <= 0 {
			hexDepth = 65536 // Default: 64KB
		}

		limitedReader := io.LimitReader(r, hexDepth)
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

// HDBCount returns the number of HDB (file hash) signatures.
func (s *ClamAVSignatureEngine) HDBCount() int {
	if s.db == nil {
		return 0
	}
	return s.db.HDB.TotalCount()
}

// NDBCount returns the number of NDB (body pattern) signatures.
func (s *ClamAVSignatureEngine) NDBCount() int {
	if s.db == nil {
		return 0
	}
	return s.db.NDB.TotalCount()
}

// MDBCount returns the number of MDB (PE section hash) signatures.
func (s *ClamAVSignatureEngine) MDBCount() int {
	if s.db == nil {
		return 0
	}
	return s.db.MDB.TotalCount()
}

// TotalSignatures returns the total signature count across all store types.
func (s *ClamAVSignatureEngine) TotalSignatures() int {
	if s.db == nil {
		return 0
	}
	return s.db.TotalSignatures()
}

// CVDVersions returns the CVD database versions keyed by filename (e.g. "main.cvd" → 62).
func (s *ClamAVSignatureEngine) CVDVersions() map[string]int {
	if s.db == nil || len(s.db.CVDVersions) == 0 {
		return nil
	}

	versions := make(map[string]int, len(s.db.CVDVersions))
	for name, hdr := range s.db.CVDVersions {
		versions[name] = hdr.Version
	}
	return versions
}
