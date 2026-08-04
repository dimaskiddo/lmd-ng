package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/quarantine"
	"github.com/dimaskiddo/lmd-ng/internal/util"
)

// ScanDataWithEngines runs the engines against a seekable reader: hash-based
// Scan first, then heuristic ScanHeuristics, short-circuiting on first match.
func ScanDataWithEngines(ctx context.Context, engines []SignatureEngine, r io.ReadSeeker, filePath string) ([]*ScanResult, error) {
	var scanErrors []error
	for _, engine := range engines {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		default:
		}

		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek reader to start for engine %s: %w", engine.Name(), err)
		}

		res, err := engine.Scan(ctx, r, filePath)
		if err != nil {
			log.Error("Signature engine scan failed", "engine", engine.Name(), "filepath", filePath, "error", err)
			scanErrors = append(scanErrors, fmt.Errorf("%s: %w", engine.Name(), err))
			continue
		}

		if len(res) > 0 {
			return res, nil
		}
	}

	for _, engine := range engines {
		hs, ok := engine.(HeuristicScanner)
		if !ok {
			continue
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		default:
		}

		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek reader for heuristic scan %s: %w", engine.Name(), err)
		}

		res, err := hs.ScanHeuristics(ctx, r, filePath)
		if err != nil {
			log.Error("Heuristic scan failed", "engine", engine.Name(), "filepath", filePath, "error", err)
			scanErrors = append(scanErrors, fmt.Errorf("%s ScanHeuristics: %w", engine.Name(), err))
			continue
		}

		if len(res) > 0 {
			return res, nil
		}
	}

	if len(scanErrors) > 0 {
		return nil, fmt.Errorf("all engines failed: %w", errors.Join(scanErrors...))
	}

	return nil, nil
}

// ScanCoordinator orchestrates file system traversal and signature scanning.
type ScanCoordinator struct {
	cfg     *config.Config
	walker  *Walker
	engines []SignatureEngine
}

// NewScanCoordinator creates a new ScanCoordinator.
func NewScanCoordinator(cfg *config.Config, walker *Walker, engines []SignatureEngine) *ScanCoordinator {
	return &ScanCoordinator{
		cfg:     cfg,
		walker:  walker,
		engines: engines,
	}
}

// getEngines returns the engine list. Engines are immutable after construction.
func (sc *ScanCoordinator) getEngines() []SignatureEngine {
	return sc.engines
}

// StartScan begins a malware scan of the specified root path. If a
// quarantine.Manager is provided, detected files are quarantined immediately.
func (sc *ScanCoordinator) StartScan(ctx context.Context, rootPath string, qMgr quarantine.Manager) ([]*ScanResult, error) {
	log.Info("Starting scan", "path", rootPath)
	var allResults []*ScanResult

	walkGroup, childCtx := errgroup.WithContext(ctx)

	var scanWg sync.WaitGroup

	maxWorkers := sc.cfg.Scanner.CPULimit
	if maxWorkers < 1 {
		maxWorkers = runtime.NumCPU()
	}

	maxConcurrency := maxWorkers * 2
	sem := make(chan struct{}, maxConcurrency)

	resultsChan := make(chan []*ScanResult, maxConcurrency)

	walkGroup.Go(func() error {
		walkErr := sc.walker.Walk(childCtx, rootPath, func(filePath string, fileInfo os.FileInfo) error {
			select {
			case <-childCtx.Done():
				return childCtx.Err()
			default:
			}

			select {
			case sem <- struct{}{}:
			case <-childCtx.Done():
				return childCtx.Err()
			}

			scanWg.Add(1)
			go func() {
				defer scanWg.Done()
				defer func() { <-sem }()
				defer func() {
					if r := recover(); r != nil {
						log.Error("Scan goroutine panicked", "file", filePath, "panic", r, "stack", debug.Stack())
					}
				}()

				fileResults, err := sc.ScanFile(childCtx, filePath)
				if err != nil {
					log.Error("Failed to scan file", "filepath", filePath, "error", err)
					return
				}

				if len(fileResults) == 0 {
					return
				}

				absFilePath, err := filepath.Abs(filePath)
				if err != nil {
					absFilePath = filePath
				}

				if qMgr != nil && sc.cfg.Quarantine.Enabled {
					log.Info("Threat detected, quarantining file", "file", absFilePath, "detections", len(fileResults))

					_, qErr := qMgr.Quarantine(childCtx, filePath, fileResults[0].SignatureName, fileResults[0].SignatureType)
					if qErr != nil {
						log.Error("Failed to quarantine file", "file", filePath, "error", qErr)
					}
				}

				resultsChan <- fileResults
			}()

			return nil
		})

		scanWg.Wait()
		close(resultsChan)

		return walkErr
	})

	var collectWg sync.WaitGroup

	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for fileResults := range resultsChan {
			allResults = append(allResults, fileResults...)
		}
	}()

	if err := walkGroup.Wait(); err != nil {
		return nil, fmt.Errorf("scan coordinator stopped with error: %w", err)
	}

	collectWg.Wait()

	log.Info("Scan finished", "path", rootPath, "total_hits", len(allResults))
	return allResults, nil
}

// ScanFile passes a file's contents to all signature engines.
func (sc *ScanCoordinator) ScanFile(ctx context.Context, filePath string) ([]*ScanResult, error) {
	info, err := os.Lstat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("File no longer exists, skipping scan", "filepath", filePath)
			return nil, nil
		}

		if os.IsPermission(err) {
			log.Warn("Permission denied to stat file", "filepath", filePath, "error", err)
			return nil, nil
		}

		return nil, fmt.Errorf("failed to stat file %s for scanning: %w", filePath, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := util.ResolveSymlink(filePath, sc.cfg.Scanner.MaxSymlinkDepth)
		if err != nil {
			log.Debug("Skipping symlink (resolution failed)", "filepath", filePath, "error", err)
			return nil, nil
		}
		info, err = os.Lstat(resolved)
		if err != nil {
			if os.IsNotExist(err) {
				log.Debug("Symlink target no longer exists", "filepath", filePath, "resolved", resolved)
				return nil, nil
			}
			if os.IsPermission(err) {
				log.Warn("Permission denied on symlink target", "filepath", filePath, "resolved", resolved)
				return nil, nil
			}
			return nil, fmt.Errorf("failed to stat symlink target %s: %w", resolved, err)
		}
		if !info.Mode().IsRegular() {
			log.Debug("Symlink target is not a regular file", "filepath", filePath, "resolved", resolved, "mode", info.Mode())
			return nil, nil
		}
		filePath = resolved
	}

	if !info.Mode().IsRegular() {
		log.Debug("Skipping non-regular file", "filepath", filePath, "mode", info.Mode())
		return nil, nil
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsPermission(err) {
			log.Warn("Permission denied to open file", "filepath", filePath, "error", err)
			return nil, nil
		}

		return nil, fmt.Errorf("failed to open file %s for scanning: %w", filePath, err)
	}
	defer file.Close()

	engines := sc.getEngines()

	fileResults, err := ScanDataWithEngines(ctx, engines, file, filePath)
	if err != nil {
		return nil, fmt.Errorf("engine scan failed for %s: %w", filePath, err)
	}

	if len(fileResults) > 0 {
		for _, r := range fileResults {
			log.Info("MALWARE DETECTED (LOCAL)",
				"file", r.FilePath,
				"signature", r.SignatureName,
				"type", r.SignatureType,
				"detection_id", r.DetectionID)
		}
	}

	return fileResults, nil
}
