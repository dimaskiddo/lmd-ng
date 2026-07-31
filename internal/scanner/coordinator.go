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

// ScanDataWithEngines runs provided signature engines against the given
// seekable reader in two passes:
//
// Pass 1 (deterministic): calls engine.Scan() on each engine — hash-only,
// zero false-positive risk. Short-circuits on first detection.
//
// Pass 2 (heuristic): calls ScanHeuristics() on engines that implement
// HeuristicScanner — pattern-based, FP-prone, gated by config. Short-circuits
// on first detection.
//
// This ordering guarantees deterministic hash matches always take priority over
// heuristic pattern matches across all engines.
func ScanDataWithEngines(ctx context.Context, engines []SignatureEngine, r io.ReadSeeker, filePath string) ([]*ScanResult, error) {
	// --- Pass 1: Hash-based scanning (deterministic, zero FP) ---
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
			// Deterministic match — no need for heuristic scan
			return res, nil
		}
	}

	// --- Pass 2: Heuristic scanning (FP-prone, gated by config) ---
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

	// If all engines failed, return aggregated error instead of silent nil
	if len(scanErrors) > 0 {
		return nil, fmt.Errorf("all engines failed: %w", errors.Join(scanErrors...))
	}

	return nil, nil
}

// ScanCoordinator orchestrates file system traversal and signature scanning.
// Used by the local fallback scan path (when DBS server is not available).
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

// getEngines returns the engine list. Engines are immutable after construction
// (set once in NewScanCoordinator), so no mutex is needed.
func (sc *ScanCoordinator) getEngines() []SignatureEngine {
	return sc.engines
}

// StartScan begins a malware scan of the specified root path. If a
// quarantine.Manager is provided, detected files are quarantined immediately.
func (sc *ScanCoordinator) StartScan(ctx context.Context, rootPath string, qMgr quarantine.Manager) ([]*ScanResult, error) {
	log.Info("Starting scan", "path", rootPath)
	var allResults []*ScanResult

	// Use an errgroup for the walker goroutine to propagate context cancellation.
	walkGroup, childCtx := errgroup.WithContext(ctx)

	// Use a separate WaitGroup for scan goroutines so we can close the results
	// channel only after ALL scan goroutines have finished, preventing
	// "send on closed channel" panics.
	var scanWg sync.WaitGroup

	// Limit concurrent scanning goroutines based on CPULimit.
	// We use a factor (e.g., 2x) to keep the CPU saturated while waiting for I/O,
	// but restrict it enough to prevent unbounded CPU spikes and memory exhaustion.
	// 0 = auto-detect (use all CPU cores).
	maxWorkers := sc.cfg.Scanner.CPULimit
	if maxWorkers < 1 {
		maxWorkers = runtime.NumCPU()
	}

	maxConcurrency := maxWorkers * 2
	sem := make(chan struct{}, maxConcurrency)

	// Channel to collect scan results from concurrent file scans
	resultsChan := make(chan []*ScanResult, maxConcurrency)

	// Goroutine that walks the file tree and spawns scan goroutines
	walkGroup.Go(func() error {
		walkErr := sc.walker.Walk(childCtx, rootPath, func(filePath string, fileInfo os.FileInfo) error {
			select {
			case <-childCtx.Done():
				return childCtx.Err()
			default:
			}

			// Acquire a semaphore slot before spawning a new goroutine.
			// This blocks the walker if we've reached max concurrency.
			select {
			case sem <- struct{}{}:
			case <-childCtx.Done():
				return childCtx.Err()
			}

			// Track each scan goroutine with the WaitGroup
			scanWg.Add(1)
			go func() {
				defer scanWg.Done()
				defer func() { <-sem }() // Release the semaphore slot when done
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

				// Ensure we log absolute path for detections
				absFilePath, err := filepath.Abs(filePath)
				if err != nil {
					absFilePath = filePath
				}

				// If quarantine manager provided and quarantine enabled, quarantine file
				if qMgr != nil && sc.cfg.Quarantine.Enabled {
					log.Info("Threat detected, quarantining file", "file", absFilePath, "detections", len(fileResults))

					_, qErr := qMgr.Quarantine(childCtx, filePath, fileResults[0].SignatureName, fileResults[0].SignatureType)
					if qErr != nil {
						log.Error("Failed to quarantine file", "file", filePath, "error", qErr)
					}
				}

				// Send results on the channel (safe because channel is only
				// closed after scanWg.Wait() completes)
				resultsChan <- fileResults
			}()

			return nil
		})

		// After Walk returns, wait for all scan goroutines to finish,
		// then close the results channel.
		scanWg.Wait()
		close(resultsChan)

		return walkErr
	})

	// Goroutine to collect results from the channel
	var collectWg sync.WaitGroup

	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for fileResults := range resultsChan {
			allResults = append(allResults, fileResults...)
		}
	}()

	// Wait for the walk goroutine (which internally waits for all scans)
	if err := walkGroup.Wait(); err != nil {
		return nil, fmt.Errorf("scan coordinator stopped with error: %w", err)
	}

	// Wait for result collection to finish
	collectWg.Wait()

	log.Info("Scan finished", "path", rootPath, "total_hits", len(allResults))
	return allResults, nil
}

// ScanFile opens a file and passes its content to all registered signature
// engines via ScanDataWithEngines. Logs detections as MALWARE DETECTED (LOCAL).
func (sc *ScanCoordinator) ScanFile(ctx context.Context, filePath string) ([]*ScanResult, error) {
	// Stat the file first to skip directories and non-regular files.
	// Use os.Lstat (not Stat) to avoid following symlinks — prevents TOCTOU
	// attacks where a symlink is substituted between stat and open.
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

	// Resolve symlinks to their true target path, limited by max_symlink_depth.
	// Skips files whose symlink chain exceeds the depth limit.
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

	// Snapshot the engine list so a concurrent swap doesn't affect this scan
	engines := sc.getEngines()

	fileResults, err := ScanDataWithEngines(ctx, engines, file, filePath)
	if err != nil {
		return nil, fmt.Errorf("engine scan failed for %s: %w", filePath, err)
	}

	// Log detections with LOCAL prefix for local fallback scan path
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
