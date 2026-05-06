package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rjeczalik/notify"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/notifier"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
)

// ScanFunc is a function that scans a single file and returns the results and
// whether the file was quarantined. This abstraction decouples the monitor from
// the ScanCoordinator, allowing both local (monolithic) and remote (DBS client)
// scan implementations.
type ScanFunc func(ctx context.Context, filePath string) ([]*scanner.ScanResult, bool)

// Monitor monitors file system events and triggers scans.
type Monitor struct {
	cfg      *config.Config
	scanFunc ScanFunc
	notifier notifier.Notifier
	events   chan notify.EventInfo
}

// NewMonitor creates and initializes a new file system monitor.
// The scanFunc callback is invoked for each file event that requires scanning.
func NewMonitor(cfg *config.Config, scanFunc ScanFunc, n notifier.Notifier) (*Monitor, error) {
	m := &Monitor{
		cfg:      cfg,
		scanFunc: scanFunc,
		notifier: n,
		// Large buffer to prevent the notify library from silently dropping
		// events via its non-blocking send. Watching broad trees like /Users
		// on macOS generates a high volume of FSEvents.
		events: make(chan notify.EventInfo, 81920000),
	}

	// Add initial paths to watch based on configuration
	for _, path := range cfg.Monitor.Paths {
		if err := m.AddPath(path); err != nil {
			log.Error("Failed to add path to monitor", "path", path, "error", err)
		}
	}

	return m, nil
}

// AddPath adds a path to the file system watcher. If the path is a directory,
// it uses notify's recursive watcher pattern ("...").
func (m *Monitor) AddPath(path string) error {
	// Evaluate symlinks so we can watch the actual directory
	if evalPath, err := filepath.EvalSymlinks(path); err == nil {
		path = evalPath
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat path %s: %w", path, err)
	}

	var watchPath string
	if info.IsDir() {
		watchPath = filepath.Join(path, "...")
	} else {
		watchPath = path
	}

	log.Info("Monitoring path", "path", watchPath)

	// Watch for Create, Write, Rename, and Remove events
	return notify.Watch(watchPath, m.events, notify.Create, notify.Write, notify.Rename, notify.Remove)
}

// isExcluded checks if a path falls under any of the configured exclude directories.
func (m *Monitor) isExcluded(eventPath string) bool {
	cleanPath := filepath.Clean(eventPath)
	for _, excluded := range m.cfg.Monitor.ExcludeDirs {
		cleanExcluded := filepath.Clean(excluded)
		if cleanPath == cleanExcluded || strings.HasPrefix(cleanPath, cleanExcluded+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// handleEvent processes a single file system event. It runs in its own goroutine
// so the main event loop can drain the channel as fast as possible, preventing
// the notify library from dropping events via its non-blocking send.
func (m *Monitor) handleEvent(ctx context.Context, eventPath string, eventType notify.Event) {
	// Skip directory events — we only scan files
	info, statErr := os.Lstat(eventPath)
	if statErr == nil && info.IsDir() {
		return
	}

	// Filter out events from excluded directories
	if m.isExcluded(eventPath) {
		log.Debug("Ignoring event in excluded directory", "path", eventPath)
		return
	}

	// Trigger scan on Create, Write, or Rename events.
	// Use bitwise AND to handle combined FSEvents flags (macOS batches flags).
	if eventType&notify.Create != 0 || eventType&notify.Write != 0 || eventType&notify.Rename != 0 {
		log.Info("File system event detected, triggering scan", "file", eventPath, "op", eventType.String())

		results, quarantined := m.scanFunc(ctx, eventPath)
		if quarantined && len(results) > 0 {
			if m.notifier != nil {
				go func() {
					if err := m.notifier.SendQuarantineNotification(eventPath, results[0].SignatureName); err != nil {
						log.Error("Failed to send quarantine notification", "error", err)
					}
				}()
			}
		}
	}
}

// Start begins monitoring file system events.
func (m *Monitor) Start(ctx context.Context) error {
	log.Info("LMD-NG file system monitor started")

	for {
		select {
		case event, ok := <-m.events:
			if !ok {
				return fmt.Errorf("notify event channel closed")
			}

			// Dispatch all slow work (Lstat, exclude check, scan) into a
			// goroutine immediately so this loop drains the channel as fast as
			// possible. The notify library uses a non-blocking send and will
			// silently drop events if the channel is full.
			go m.handleEvent(ctx, event.Path(), event.Event())

		case <-ctx.Done():
			log.Info("LMD-NG file system monitor stopped")
			notify.Stop(m.events)
			return nil
		}
	}
}

// Stop stops the file system monitor.
func (m *Monitor) Stop() error {
	notify.Stop(m.events)
	return nil
}
