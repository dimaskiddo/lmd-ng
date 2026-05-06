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
		events:   make(chan notify.EventInfo, 1024), // Buffer to handle bursts of events
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

// Start begins monitoring file system events.
func (m *Monitor) Start(ctx context.Context) error {
	log.Info("LMD-NG file system monitor started")

	for {
		select {
		case event, ok := <-m.events:
			if !ok {
				return fmt.Errorf("notify event channel closed")
			}

			log.Debug("Notify event received", "event", event.Event().String(), "path", event.Path())

			// Filter out events from excluded directories
			isExcluded := false
			cleanEventName := filepath.Clean(event.Path())
			for _, excluded := range m.cfg.Monitor.ExcludeDirs {
				cleanExcluded := filepath.Clean(excluded)
				if cleanEventName == cleanExcluded || strings.HasPrefix(cleanEventName, cleanExcluded+string(filepath.Separator)) {
					log.Debug("Ignoring event in excluded directory", "path", event.Path())
					isExcluded = true
					break
				}
			}

			if isExcluded {
				continue
			}

			// Only act on relevant file operations for now
			// notify.Remove is useful for cleanup, but we only trigger scans on Create/Write/Rename
			if event.Event()&notify.Create != 0 || event.Event()&notify.Write != 0 || event.Event()&notify.Rename != 0 {
				// Trigger a scan for the affected file
				log.Info("File system event detected, triggering scan", "file", event.Path(), "op", event.Event().String())
				go func(filePath string) {
					results, quarantined := m.scanFunc(ctx, filePath)
					if quarantined && len(results) > 0 {
						if m.notifier != nil {
							// Fire and forget: send notification asynchronously
							go func() {
								if err := m.notifier.SendQuarantineNotification(filePath, results[0].SignatureName); err != nil {
									log.Error("Failed to send quarantine notification", "error", err)
								}
							}()
						}
					}
				}(event.Path()) // Run scan + quarantine in a goroutine
			}

			// Note: With rjeczalik/notify's recursive watch ("..."), we do NOT need to manually
			// add new directories to the watcher when a Create event happens. The native
			// FSEvents (macOS) and automated inotify trees (Linux) handle it automatically.

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
