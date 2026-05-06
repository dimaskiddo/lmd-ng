//go:build darwin

package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsevents"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// darwinMonitor implements monitorImpl using macOS FSEvents.
// FSEvents natively supports recursive directory watching without requiring
// a file descriptor per watched directory, eliminating kqueue limits entirely.
type darwinMonitor struct {
	parent  *Monitor
	streams []*fsevents.EventStream
}

func newPlatformMonitor(m *Monitor) (monitorImpl, error) {
	dm := &darwinMonitor{parent: m}

	for _, path := range m.cfg.Monitor.Paths {
		if evalPath, err := filepath.EvalSymlinks(path); err == nil {
			path = evalPath
		}

		info, err := os.Stat(path)
		if err != nil {
			log.Error("Failed to stat monitor path", "path", path, "error", err)
			continue
		}

		if !info.IsDir() {
			log.Warn("FSEvents only watches directories, skipping file", "path", path)
			continue
		}

		// Pre-create a BUFFERED Events channel. The fsnotify/fsevents library
		// creates an unbuffered channel by default in EventStream.Start() if
		// Events is nil. The FSEvents callback runs on a GCD serial dispatch
		// queue and performs a blocking send (es.Events <- events). If no
		// goroutine is reading yet when the first callback fires (highly likely
		// on busy directories like /private/tmp or /Users), the dispatch queue
		// thread blocks permanently — no more events are ever delivered.
		//
		// By pre-creating a buffered channel, early callbacks can enqueue
		// without blocking, giving the reader goroutine time to start.
		es := &fsevents.EventStream{
			Paths:   []string{path},
			Latency: 200 * time.Millisecond,
			Flags:   fsevents.FileEvents | fsevents.NoDefer,
			Events:  make(chan []fsevents.Event, 8192),
		}

		dm.streams = append(dm.streams, es)
		log.Info("Monitoring path", "path", path, "backend", "fsevents")
	}

	if len(dm.streams) == 0 {
		return nil, fmt.Errorf("no valid paths to monitor")
	}

	return dm, nil
}

// isExcluded checks if a path falls under any of the configured exclude directories.
func (dm *darwinMonitor) isExcluded(eventPath string) bool {
	cleanPath := filepath.Clean(eventPath)
	for _, excluded := range dm.parent.cfg.Monitor.ExcludeDirs {
		cleanExcluded := filepath.Clean(excluded)

		if cleanPath == cleanExcluded || strings.HasPrefix(cleanPath, cleanExcluded+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

// handleEvent processes a single FSEvents event.
func (dm *darwinMonitor) handleEvent(ctx context.Context, path string, flags fsevents.EventFlags) {
	log.Debug("Monitor event received", "path", path, "flags", fmt.Sprintf("0x%x", flags))

	// Skip directory events — we only scan files
	info, statErr := os.Lstat(path)
	if statErr == nil && info.IsDir() {
		return
	}

	// Filter excluded paths
	if dm.isExcluded(path) {
		log.Debug("Monitor event skipped (excluded)", "path", path)
		return
	}

	// Only trigger scans on create, modify, or rename
	isCreate := flags&fsevents.ItemCreated != 0
	isModify := flags&fsevents.ItemModified != 0
	isRename := flags&fsevents.ItemRenamed != 0

	if isCreate || isModify || isRename {
		log.Info("File system event detected, triggering scan", "file", path, "flags", fmt.Sprintf("0x%x", flags))

		results, quarantined := dm.parent.scanFunc(ctx, path)
		if quarantined && len(results) > 0 {
			if dm.parent.notifier != nil {
				go func() {
					if err := dm.parent.notifier.SendQuarantineNotification(path, results[0].SignatureName); err != nil {
						log.Error("Failed to send quarantine notification", "error", err)
					}
				}()
			}
		}
	} else {
		log.Debug("Monitor event skipped (non-actionable flags)", "path", path, "flags", fmt.Sprintf("0x%x", flags))
	}
}

// Start begins monitoring using FSEvents. It starts reader goroutines FIRST,
// then starts the streams to prevent dispatch queue deadlocks.
func (dm *darwinMonitor) Start(ctx context.Context) error {
	// Multiplex all stream event channels into a single merged channel.
	// CRITICAL: set up readers BEFORE starting streams to prevent the GCD
	// dispatch queue from blocking on the first callback.
	merged := make(chan fsevents.Event, 4096)

	for _, es := range dm.streams {
		go func(events chan []fsevents.Event) {
			for batch := range events {
				for _, ev := range batch {
					merged <- ev
				}
			}
		}(es.Events)
	}

	// Now start all FSEvent streams — readers are already waiting.
	for _, es := range dm.streams {
		if err := es.Start(); err != nil {
			log.Error("Failed to start FSEvents stream", "paths", es.Paths, "error", err)
		}
	}

	log.Info("File system monitor started", "backend", "fsevents", "streams", len(dm.streams))

	for {
		select {
		case ev := <-merged:
			go dm.handleEvent(ctx, ev.Path, ev.Flags)

		case <-ctx.Done():
			log.Info("File system monitor stopped", "backend", "fsevents")
			for _, es := range dm.streams {
				es.Stop()
			}

			return nil
		}
	}
}

// Stop stops all FSEvent streams.
func (dm *darwinMonitor) Stop() error {
	for _, es := range dm.streams {
		es.Stop()
	}

	return nil
}
