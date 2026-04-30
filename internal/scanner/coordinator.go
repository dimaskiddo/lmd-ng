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

// ScanCoordinator orchestrates file system traversal and signature scanning.
type ScanCoordinator struct {
	cfg           *config.Config
	walker        *Walker
	engines       []SignatureEngine
	enginesMu     sync.RWMutex
	quarantineMgr quarantine.Manager

	// EngineFactory is called during ReloadEngines to reconstruct the
	// signature engine list. It is set by the daemon at wiring time.
	EngineFactory func(cfg *config.Config) ([]SignatureEngine, error)
}

// NewScanCoordinator creates a new ScanCoordinator.
func NewScanCoordinator(cfg *config.Config, walker *Walker, engines []SignatureEngine) *ScanCoordinator {
	return &ScanCoordinator{
		cfg:           cfg,
		walker:        walker,
		engines:       engines,
		quarantineMgr: quarantine.NewQuarantineManager(&cfg.Quarantine),
	}
}

// ReloadEngines re-creates all signature engines from their database files.
// This is safe to call while scans are running — active scans will continue
// using the old engine set until they finish, while new scans will pick up
// the freshly loaded engines.
func (sc *ScanCoordinator) ReloadEngines() error {
	if sc.EngineFactory == nil {
		return fmt.Errorf("engine factory not set, cannot reload engines")
	}

	log.Info("Reloading signature engines...")

	newEngines, err := sc.EngineFactory(sc.cfg)
	if err != nil {
		return fmt.Errorf("failed to create new signature engines during reload: %w", err)
	}

	sc.enginesMu.Lock()
	sc.engines = newEngines
	sc.enginesMu.Unlock()

	engineNames := make([]string, len(newEngines))
	for i, e := range newEngines {
		engineNames[i] = e.Name()
	}

	log.Info("Signature engines reloaded successfully", "engines", engineNames)
	return nil
}

// getEngines returns a snapshot of the current engine list, safe for use
// during a scan even if a reload happens concurrently.
func (sc *ScanCoordinator) getEngines() []SignatureEngine {
	sc.enginesMu.RLock()
	defer sc.enginesMu.RUnlock()

	// Return a copy of the slice header so the caller holds a stable reference
	engines := make([]SignatureEngine, len(sc.engines))
	copy(engines, sc.engines)

	return engines
}

// StartScan begins a malware scan of the specified root path.
func (sc *ScanCoordinator) StartScan(ctx context.Context, rootPath string) ([]*ScanResult, error) {
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

				// If quarantine is enabled, quarantine the file (once per file)
				if sc.cfg.Quarantine.Enabled {
					log.Info("Threat detected, quarantining file", "file", filePath, "detections", len(fileResults))

					_, qErr := sc.quarantineMgr.Quarantine(childCtx, filePath, fileResults[0].SignatureName, fileResults[0].SignatureType)
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

// ScanFileAndAct scans a single file and immediately takes action (quarantine)
// if malware is detected. This is intended for real-time monitor use where
// detected threats must be handled immediately rather than collected into a
// batch result set.
func (sc *ScanCoordinator) ScanFileAndAct(ctx context.Context, filePath string) ([]*ScanResult, bool) {
	fileResults, err := sc.ScanFile(ctx, filePath)
	if err != nil {
		log.Error("Failed to scan file", "filepath", filePath, "error", err)
		return nil, false
	}

	if len(fileResults) == 0 {
		return nil, false
	}

	quarantined := false

	// If quarantine is enabled, quarantine the file immediately
	if sc.cfg.Quarantine.Enabled {
		log.Info("Threat detected, quarantining file", "file", filePath, "detections", len(fileResults))

		_, qErr := sc.quarantineMgr.Quarantine(ctx, filePath, fileResults[0].SignatureName, fileResults[0].SignatureType)
		if qErr != nil {
			log.Error("Failed to quarantine file", "file", filePath, "error", qErr)
		} else {
			quarantined = true
		}
	}

	return fileResults, quarantined
}

// ScanFile opens a file and passes its content to all registered signature engines.
func (sc *ScanCoordinator) ScanFile(ctx context.Context, filePath string) ([]*ScanResult, error) {
	// Stat the file first to skip directories and non-regular files
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

	var fileResults []*ScanResult

	// Snapshot the engine list so a concurrent reload doesn't affect this scan
	engines := sc.getEngines()

	for _, engine := range engines {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Resetting the file offset for each engine to ensure each engine starts from the beginning
		_, err = file.Seek(0, io.SeekStart)
		if err != nil {
			return nil, fmt.Errorf("failed to seek file to start for engine %s: %w", engine.Name(), err)
		}

		res, err := engine.Scan(ctx, file, filePath)
		if err != nil {
			log.Error("Signature engine failed to scan file", "engine", engine.Name(), "filepath", filePath, "error", err)
			continue
		}

		if len(res) > 0 {
			fileResults = append(fileResults, res...)
			// Stop scanning with remaining engines once malware is detected.
			// One positive detection is sufficient to trigger quarantine.
			break
		}
	}

	// Log if any malware hits were found for the file
	if len(fileResults) > 0 {
		for _, r := range fileResults {
			log.Info("MALWARE DETECTED",
				"file", r.FilePath,
				"signature", r.SignatureName,
				"type", r.SignatureType,
				"detection_id", r.DetectionID)
		}
	}

	return fileResults, nil
}
