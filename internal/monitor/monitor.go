package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
)

// Monitor monitors file system events and triggers scans.
type Monitor struct {
	cfg         *config.Config
	watcher     *fsnotify.Watcher
	coordinator *scanner.ScanCoordinator
	events      chan fsnotify.Event
	errors      chan error
}

// NewMonitor creates and initializes a new file system monitor.
func NewMonitor(cfg *config.Config, coordinator *scanner.ScanCoordinator) (*Monitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	m := &Monitor{
		cfg:         cfg,
		watcher:     watcher,
		coordinator: coordinator,
		events:      make(chan fsnotify.Event),
		errors:      make(chan error),
	}

	// Add initial paths to watch based on configuration
	for _, path := range cfg.Monitor.Paths {
		if err := m.AddRecursive(path); err != nil {
			log.Error("Failed to add path to monitor", "path", path, "error", err)
		}
	}

	return m, nil
}

// AddRecursive adds a path and all its subdirectories to the file system watcher.
func (m *Monitor) AddRecursive(path string) error {
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// Log permission errors but continue walking
			if os.IsPermission(err) {
				log.Warn("Permission denied when accessing path", "path", p, "error", err)
				return filepath.SkipDir
			}

			log.Error("Error walking path", "path", p, "error", err)
			return err
		}

		// Check for excluded directories
		for _, excluded := range m.cfg.Monitor.ExcludeDirs {
			if p == excluded {
				log.Debug("Excluding directory from monitoring", "path", p)
				return filepath.SkipDir
			}
		}

		if d.IsDir() {
			absPath, err := filepath.Abs(p)
			if err != nil {
				log.Error("Failed to get absolute path", "path", p, "error", err)
				return err
			}

			if err := m.watcher.Add(absPath); err != nil {
				log.Error("Failed to add path to watcher", "path", absPath, "error", err)
				return err
			}

			log.Info("Monitoring directory", "path", absPath)
		}

		return nil
	})
}

// Start begins monitoring file system events.
func (m *Monitor) Start(ctx context.Context) error {
	log.Info("LMD-NG file system monitor started")

	for {
		select {
		case event, ok := <-m.watcher.Events:
			if !ok {
				return fmt.Errorf("fsnotify event channel closed")
			}

			log.Debug("FSNotify event received", "event", event.String())

			// Filter out events from excluded directories
			for _, excluded := range m.cfg.Monitor.ExcludeDirs {
				if strings.HasPrefix(event.Name, excluded) {
					log.Debug("Ignoring event in excluded directory", "path", event.Name)
					continue
				}
			}

			// Only act on relevant file operations for now
			if event.Op&fsnotify.Create == fsnotify.Create ||
				event.Op&fsnotify.Write == fsnotify.Write ||
				event.Op&fsnotify.Rename == fsnotify.Rename {
				// Trigger a scan for the affected file
				log.Info("File system event detected, triggering scan", "file", event.Name, "op", event.Op.String())
				go m.coordinator.ScanFileAndAct(ctx, event.Name) // Run scan + quarantine in a goroutine
			}

			// If a directory is created, add it to the watcher recursively
			if event.Op&fsnotify.Create == fsnotify.Create {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					log.Info("New directory created, adding to monitor", "path", event.Name)
					if err := m.AddRecursive(event.Name); err != nil {
						log.Error("Failed to add new directory to monitor", "path", event.Name, "error", err)
					}
				}
			}

		case err, ok := <-m.watcher.Errors:
			if !ok {
				return fmt.Errorf("fsnotify error channel closed")
			}
			log.Error("FSNotify error", "error", err)

		case <-ctx.Done():
			log.Info("LMD-NG file system monitor stopped")
			return m.watcher.Close()
		}
	}
}

// Stop stops the file system monitor.
func (m *Monitor) Stop() error {
	return m.watcher.Close()
}
