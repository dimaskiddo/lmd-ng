//go:build !darwin

package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// otherMonitor implements monitorImpl using fsnotify (inotify on Linux,
// ReadDirectoryChangesW on Windows). It recursively walks directories and
// adds each one individually to the watcher.
type otherMonitor struct {
	parent  *Monitor
	watcher *fsnotify.Watcher
}

func newPlatformMonitor(m *Monitor) (monitorImpl, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	om := &otherMonitor{
		parent:  m,
		watcher: watcher,
	}

	for _, path := range m.cfg.Monitor.Paths {
		if err := om.addRecursive(path); err != nil {
			log.Error("Failed to add path to monitor", "path", path, "error", err)
		}
	}

	return om, nil
}

// isExcluded checks if a path falls under any of the configured exclude directories.
func (om *otherMonitor) isExcluded(path string) bool {
	cleanPath := filepath.Clean(path)
	for _, excluded := range om.parent.cfg.Monitor.ExcludeDirs {
		cleanExcluded := filepath.Clean(excluded)
		if cleanPath == cleanExcluded || strings.HasPrefix(cleanPath, cleanExcluded+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// addRecursive adds a path and all its subdirectories to the watcher.
func (om *otherMonitor) addRecursive(path string) error {
	if evalPath, err := filepath.EvalSymlinks(path); err == nil {
		path = evalPath
	}

	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				log.Warn("Permission denied when accessing path", "path", p, "error", err)
				return filepath.SkipDir
			}
			log.Warn("Error walking path, skipping", "path", p, "error", err)
			return filepath.SkipDir
		}

		if om.isExcluded(p) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			absPath, absErr := filepath.Abs(p)
			if absErr != nil {
				log.Warn("Failed to get absolute path, skipping", "path", p, "error", absErr)
				return nil
			}

			if addErr := om.watcher.Add(absPath); addErr != nil {
				log.Warn("Failed to add path to watcher, continuing", "path", absPath, "error", addErr)
				return nil
			}
			log.Debug("Monitoring directory", "path", absPath)
		}

		return nil
	})
}

// handleEvent processes a single fsnotify event.
func (om *otherMonitor) handleEvent(ctx context.Context, name string, op fsnotify.Op) {
	// If a new directory is created, add it to the watcher recursively
	info, statErr := os.Lstat(name)
	if statErr == nil && info.IsDir() {
		if op&fsnotify.Create != 0 {
			log.Info("New directory created, adding to monitor", "path", name)
			if err := om.addRecursive(name); err != nil {
				log.Error("Failed to add new directory to monitor", "path", name, "error", err)
			}
		}
		return
	}

	if om.isExcluded(name) {
		return
	}

	if op&fsnotify.Create != 0 || op&fsnotify.Write != 0 || op&fsnotify.Rename != 0 {
		log.Info("File system event detected, triggering scan", "file", name, "op", op.String())

		results, quarantined := om.parent.scanFunc(ctx, name)
		if quarantined && len(results) > 0 {
			if om.parent.notifier != nil {
				go func() {
					if err := om.parent.notifier.SendQuarantineNotification(name, results[0].SignatureName); err != nil {
						log.Error("Failed to send quarantine notification", "error", err)
					}
				}()
			}
		}
	}
}

// Start begins monitoring using fsnotify.
func (om *otherMonitor) Start(ctx context.Context) error {
	log.Info("LMD-NG file system monitor started (fsnotify)", "watched_dirs", len(om.watcher.WatchList()))

	for {
		select {
		case event, ok := <-om.watcher.Events:
			if !ok {
				return fmt.Errorf("fsnotify event channel closed")
			}
			go om.handleEvent(ctx, event.Name, event.Op)

		case err, ok := <-om.watcher.Errors:
			if !ok {
				return fmt.Errorf("fsnotify error channel closed")
			}
			log.Error("FSNotify error", "error", err)

		case <-ctx.Done():
			log.Info("LMD-NG file system monitor stopped")
			return om.watcher.Close()
		}
	}
}

// Stop stops the fsnotify watcher.
func (om *otherMonitor) Stop() error {
	return om.watcher.Close()
}
