package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/quarantine"
)

// ScanDataWithEngines runs all provided signature engines against the given
// seekable reader. It is the single source of truth for the engine-scan loop.
// Callers are responsible for logging detections with their own context prefix.
// Returns matched results and any fatal error.
func ScanDataWithEngines(ctx context.Context, engines []SignatureEngine, r io.ReadSeeker, filePath string) ([]*ScanResult, error) {
	var results []*ScanResult

	for _, engine := range engines {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		default:
		}

		// Rewind reader for each engine so every engine starts from byte 0
		if _, err := r.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("failed to seek reader to start for engine %s: %w", engine.Name(), err)
		}

		res, err := engine.Scan(ctx, r, filePath)
		if err != nil {
			log.Error("Signature engine failed to scan", "engine", engine.Name(), "filepath", filePath, "error", err)
			continue
		}

		if len(res) > 0 {
			results = append(results, res...)
			// Stop scanning with remaining engines once malware is detected.
			// One positive detection is sufficient to trigger quarantine.
			break
		}
	}

	return results, nil
}

// ScanCoordinator orchestrates file system traversal and signature scanning.
// Used by the local fallback scan path (when DBS server is not available).
type ScanCoordinator struct {
	cfg       *config.Config
	walker    *Walker
	engines   []SignatureEngine
	enginesMu sync.RWMutex
}

// NewScanCoordinator creates a new ScanCoordinator.
func NewScanCoordinator(cfg *config.Config, walker *Walker, engines []SignatureEngine) *ScanCoordinator {
	return &ScanCoordinator{
		cfg:     cfg,
		walker:  walker,
		engines: engines,
	}
}

// getEngines returns a snapshot of the current engine list, safe for use
// during a scan even if engines are swapped concurrently.
func (sc *ScanCoordinator) getEngines() []SignatureEngine {
	sc.enginesMu.RLock()
	defer sc.enginesMu.RUnlock()

	// Return a copy of the slice header so the caller holds a stable reference
	engines := make([]SignatureEngine, len(sc.engines))
	copy(engines, sc.engines)

	return engines
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

	// Channel to collect scan results from concurrent file scans
	resultsChan := make(chan []*ScanResult)

	// Limit concurrent scanning goroutines based on CPULimit.
	// We use a factor (e.g., 2x) to keep the CPU saturated while waiting for I/O,
	// but restrict it enough to prevent unbounded CPU spikes and memory exhaustion.
	maxWorkers := sc.cfg.Scanner.CPULimit
	if maxWorkers < 1 {
		maxWorkers = 1
	}

	maxConcurrency := maxWorkers * 2
	sem := make(chan struct{}, maxConcurrency)

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

				fileResults, err := sc.ScanFile(childCtx, filePath)
				if err != nil {
					log.Error("Failed to scan file", "filepath", filePath, "error", err)
					return
				}

				if len(fileResults) == 0 {
					return
				}

				// If quarantine manager provided and quarantine enabled, quarantine file
				if qMgr != nil && sc.cfg.Quarantine.Enabled {
					log.Info("Threat detected, quarantining file", "file", filePath, "detections", len(fileResults))

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
	// Use os.Stat (not Lstat) to follow symlinks and resolve Docker volume mounts.
	info, err := os.Stat(filePath)
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
		return nil, err
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
