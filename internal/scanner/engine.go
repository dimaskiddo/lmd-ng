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
	SignatureName string
	SignatureType string
	FilePath      string
	DetectionID   string
}

// SignatureEngine defines the contract for malware signature matching engines.
type SignatureEngine interface {
	// Scan returns all detected matches. It must not close the reader.
	Scan(ctx context.Context, r io.ReadSeeker, filePath string) ([]*ScanResult, error)
	// Name returns the name of the signature engine.
	Name() string
}

// HeuristicScanner is an optional interface for engines that perform pattern
// (HEX, NDB) matching in a separate pass.
type HeuristicScanner interface {
	ScanHeuristics(ctx context.Context, r io.ReadSeeker, filePath string) ([]*ScanResult, error)
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
		log.Info("RXFN signatures loaded",
			"hdb_total", clamavS.HDB.TotalCount(),
			"mdb_total", clamavS.MDB.TotalCount(),
			"ndb_total", clamavS.NDB.TotalCount(),
			"total_signatures", clamavS.TotalSignatures())
	} else {
		log.Debug("No RXFN signatures found", "path", rfxnPath)
	}

	if cfg.Scanner.IsHeuristicEnabled("hex") && hexS != nil && hexS.Count() > 0 {
		log.Warn("HEX heuristic enabled — may produce false positives",
			"hex_sigs", hexS.Count())
	}
	if cfg.Scanner.IsHeuristicEnabled("ndb") && clamavS != nil && clamavS.NDB.TotalCount() > 0 {
		log.Warn("NDB heuristic enabled — may produce false positives",
			"ndb_sigs", clamavS.NDB.TotalCount())
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
	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()
	multiWriter := io.MultiWriter(md5Hasher, sha1Hasher, sha256Hasher)

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek reader to start for hash: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		n, readErr := r.Read(buf)
		if n > 0 {
			if _, wErr := multiWriter.Write(buf[:n]); wErr != nil {
				return nil, fmt.Errorf("hash write failed: %w", wErr)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("failed to calculate hash: %w", readErr)
		}
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

	if s.clamavScanner != nil {
		var fileSize int64 = -1
		if file, ok := r.(*os.File); ok {
			if info, err := file.Stat(); err == nil {
				fileSize = info.Size()
			}
		} else {
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
	}

	if s.clamavScanner != nil && s.clamavScanner.MDB.TotalCount() > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if _, err := r.Seek(0, io.SeekStart); err == nil {
			magicBuf := make([]byte, 512)
			n, readErr := io.ReadFull(r, magicBuf)
			if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
				log.Debug("Failed to read magic bytes for RFXN PE detection", "error", readErr)
			}
			if n > 0 {
				if detectMagicType(magicBuf[:n]) == magicTypePE {
					sections, peErr := ParsePESections(r)
					if peErr == nil {
						for _, section := range sections {
							if s.isPathAllowlisted(filePath) {
								break
							}
							if entry, ok := s.clamavScanner.MDB.LookupMD5(section.MD5, section.Size); ok {
								return []*ScanResult{{
									SignatureName: entry.Name,
									SignatureType: "RFXN-MDB",
									FilePath:      filePath,
									DetectionID:   fmt.Sprintf("rfxn.mdb.%s.%s", section.Name, section.MD5),
								}}, nil
							}
							if entry, ok := s.clamavScanner.MDB.LookupSHA1(section.SHA1, section.Size); ok {
								return []*ScanResult{{
									SignatureName: entry.Name,
									SignatureType: "RFXN-MDB",
									FilePath:      filePath,
									DetectionID:   fmt.Sprintf("rfxn.mdb.%s.%s", section.Name, section.SHA1),
								}}, nil
							}
							if entry, ok := s.clamavScanner.MDB.LookupSHA256(section.SHA256, section.Size); ok {
								return []*ScanResult{{
									SignatureName: entry.Name,
									SignatureType: "RFXN-MDB",
									FilePath:      filePath,
									DetectionID:   fmt.Sprintf("rfxn.mdb.%s.%s", section.Name, section.SHA256),
								}}, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, nil
}

// ScanHeuristics performs heuristic pattern scanning (HEX + NDB) for the LMD
// engine. Called in the heuristic pass after all engines complete hash-based Scan.
func (s *LMDSignatureScanner) ScanHeuristics(ctx context.Context, r io.ReadSeeker, filePath string) ([]*ScanResult, error) {
	hexOn := s.cfg.Scanner.IsHeuristicEnabled("hex") && s.hexScanner != nil && s.hexScanner.Count() > 0
	ndbOn := s.cfg.Scanner.IsHeuristicEnabled("ndb") && s.clamavScanner != nil && s.clamavScanner.NDB.TotalCount() > 0

	if !hexOn && !ndbOn {
		return nil, nil
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek reader for heuristic scan: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	hexDepth := int64(s.cfg.Scanner.HexDepth)
	if hexDepth <= 0 {
		hexDepth = 65536
	}
	content, err := io.ReadAll(io.LimitReader(r, hexDepth))
	if err != nil {
		return nil, fmt.Errorf("failed to read content for heuristic scan: %w", err)
	}

	// Determine fileSize for NDB matching
	var fileSize int64 = -1
	if file, ok := r.(*os.File); ok {
		if info, err := file.Stat(); err == nil {
			fileSize = info.Size()
		}
	} else {
		if size, err := r.Seek(0, io.SeekEnd); err == nil {
			fileSize = size
		}
	}

	if hexOn {
		if matches := s.hexScanner.Check(content, filePath); len(matches) > 0 {
			return []*ScanResult{{
				SignatureName: matches[0],
				SignatureType: "HEX",
				FilePath:      filePath,
				DetectionID:   fmt.Sprintf("hex.%s", matches[0]),
			}}, nil
		}
	}

	if ndbOn {
		if matches := s.clamavScanner.NDB.Match(content, fileSize); len(matches) > 0 {
			return []*ScanResult{{
				SignatureName: matches[0],
				SignatureType: "RFXN-NDB",
				FilePath:      filePath,
				DetectionID:   fmt.Sprintf("rfxn.ndb.%s", matches[0]),
			}}, nil
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
	if s.hexScanner == nil || !s.cfg.Scanner.IsHeuristicEnabled("hex") {
		return 0
	}
	return s.hexScanner.Count()
}

// RFXNCount returns the total number of RFXN ClamAV signatures (NDB + HDB + MDB).
// When NDB heuristic is disabled, NDB count is excluded from the total.
func (s *LMDSignatureScanner) RFXNCount() int {
	if s.clamavScanner == nil {
		return 0
	}
	total := s.clamavScanner.TotalSignatures()
	if !s.cfg.Scanner.IsHeuristicEnabled("ndb") {
		total -= s.clamavScanner.NDB.TotalCount()
	}
	return total
}

// isPathAllowlisted reports whether filePath starts with a configured
// HashAllowlistPaths prefix.
func (s *LMDSignatureScanner) isPathAllowlisted(filePath string) bool {
	for _, prefix := range s.cfg.Scanner.HashAllowlistPaths {
		if strings.HasPrefix(filePath, prefix) {
			return true
		}
	}
	return false
}

// ClamAVSignatureEngine matches against ClamAV signature databases.
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

	if cfg.Scanner.IsHeuristicEnabled("ndb") && db.NDB.TotalCount() > 0 {
		log.Warn("NDB heuristic enabled — may produce false positives",
			"ndb_sigs", db.NDB.TotalCount())
	}

	return &ClamAVSignatureEngine{
		cfg: cfg,
		db:  db,
	}, nil
}

// Scan implements the SignatureEngine interface for ClamAVSignatureEngine.
func (s *ClamAVSignatureEngine) Scan(ctx context.Context, r io.ReadSeeker, filePath string) ([]*ScanResult, error) {
	var fileSize int64 = -1
	if file, ok := r.(*os.File); ok {
		if info, err := file.Stat(); err == nil {
			fileSize = info.Size()
		}
	} else {
		if size, err := r.Seek(0, io.SeekEnd); err == nil {
			fileSize = size
		}
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to start for hash computation: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	md5Hasher := md5.New()
	sha1Hasher := sha1.New()
	sha256Hasher := sha256.New()
	multiHashWriter := io.MultiWriter(md5Hasher, sha1Hasher, sha256Hasher)

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		n, readErr := r.Read(buf)
		if n > 0 {
			if _, wErr := multiHashWriter.Write(buf[:n]); wErr != nil {
				return nil, fmt.Errorf("hash write failed: %w", wErr)
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("failed to compute file hashes: %w", readErr)
		}
	}

	md5Hash := hex.EncodeToString(md5Hasher.Sum(nil))
	sha1Hash := hex.EncodeToString(sha1Hasher.Sum(nil))
	sha256Hash := hex.EncodeToString(sha256Hasher.Sum(nil))

	if entry, found := s.db.HDB.LookupMD5(md5Hash, fileSize); found {
		return []*ScanResult{{
			SignatureName: entry.Name,
			SignatureType: "ClamAV-MD5",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("clamav.md5.%s", md5Hash),
		}}, nil
	}

	if entry, found := s.db.HDB.LookupSHA1(sha1Hash, fileSize); found {
		return []*ScanResult{{
			SignatureName: entry.Name,
			SignatureType: "ClamAV-SHA1",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("clamav.sha1.%s", sha1Hash),
		}}, nil
	}

	if entry, found := s.db.HDB.LookupSHA256(sha256Hash, fileSize); found {
		return []*ScanResult{{
			SignatureName: entry.Name,
			SignatureType: "ClamAV-SHA256",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("clamav.sha256.%s", sha256Hash),
		}}, nil
	}

	if s.db.MDB.TotalCount() > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if _, err := r.Seek(0, io.SeekStart); err == nil {
			magicBuf := make([]byte, 512)
			n, readErr := io.ReadFull(r, magicBuf)
			if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
				log.Debug("Failed to read magic bytes for ClamAV PE detection", "error", readErr)
			}
			if n > 0 {
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

	return nil, nil
}

// ScanHeuristics performs ClamAV NDB body-pattern scanning for the ClamAV
// engine. Called in the heuristic pass after all engines complete hash-based Scan.
func (s *ClamAVSignatureEngine) ScanHeuristics(ctx context.Context, r io.ReadSeeker, filePath string) ([]*ScanResult, error) {
	if !s.cfg.Scanner.IsHeuristicEnabled("ndb") || s.db == nil || s.db.NDB.TotalCount() == 0 {
		return nil, nil
	}

	// Determine file size for NDB matching
	var fileSize int64 = -1
	if file, ok := r.(*os.File); ok {
		if info, err := file.Stat(); err == nil {
			fileSize = info.Size()
		}
	} else {
		if size, err := r.Seek(0, io.SeekEnd); err == nil {
			fileSize = size
		}
	}

	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to start for NDB scan: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	hexDepth := int64(s.cfg.Scanner.ClamAVHexDepth)
	if hexDepth <= 0 {
		hexDepth = 65536
	}

	content, err := io.ReadAll(io.LimitReader(r, hexDepth))
	if err != nil {
		return nil, fmt.Errorf("failed to read content for NDB scan: %w", err)
	}

	var results []*ScanResult
	ndbMatches := s.db.NDB.Match(content, fileSize)
	for _, sigName := range ndbMatches {
		results = append(results, &ScanResult{
			SignatureName: sigName,
			SignatureType: "ClamAV-NDB",
			FilePath:      filePath,
			DetectionID:   fmt.Sprintf("clamav.ndb.%s", sigName),
		})
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
	if s.db == nil || !s.cfg.Scanner.IsHeuristicEnabled("ndb") {
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
	total := s.db.TotalSignatures()
	if !s.cfg.Scanner.IsHeuristicEnabled("ndb") {
		total -= s.db.NDB.TotalCount()
	}
	return total
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
