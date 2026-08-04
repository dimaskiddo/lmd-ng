//go:build linux

package atp

import (
	"context"
	"path/filepath"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/fsnotify/fsnotify"
)

// startInotifyMonitor watches protected files for tamper signals and re-applies
// the immutable flag when cleared.
func (p *Protector) startInotifyMonitor(ctx context.Context, files []string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Warn("ATP: inotify watcher init failed — periodic recheck still active",
			"error", err)
		return
	}
	defer w.Close()

	for _, f := range files {
		dir := filepath.Dir(f)
		if err := w.Add(dir); err != nil {
			log.Debug("ATP: inotify watch add failed", "dir", dir, "error", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if !isProtectedPath(ev.Name, files) {
				continue
			}

			switch {
			case ev.Op&fsnotify.Chmod != 0:
				log.Warn("ATP: protected file attribute change detected — re-applying immutable flag",
					"file", ev.Name)
				p.recheckFiles(withPath(ev.Name))
			case ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Remove|fsnotify.Rename) != 0:
				log.Warn("ATP: protected file modification detected", "file", ev.Name)
				p.recheckFiles(withPath(ev.Name))
			}
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			log.Debug("ATP: inotify watcher error", "error", err)
		}
	}
}

// isProtectedPath reports whether path refers to one of the protected files.
func isProtectedPath(path string, files []string) bool {
	clean := filepath.Clean(path)
	for _, f := range files {
		if filepath.Clean(f) == clean {
			return true
		}
	}
	return false
}

// withPath returns a single-element slice containing path.
func withPath(path string) []string {
	return []string{path}
}
