//go:build linux

package atp

import (
	"context"
	"path/filepath"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/fsnotify/fsnotify"
)

// startInotifyMonitor observes protected files for tamper signals:
//
//   - Chmod (IN_ATTRIB on Linux): someone ran "chattr -i" to clear the
//     immutable flag so the file can be modified.
//   - Write / Create / Remove / Rename: direct modification, deletion, or
//     replacement of a protected file (only observable if the file is on a
//     filesystem where the immutable flag failed to apply, since a set +i
//     flag normally blocks these).
//
// On a tamper signal it re-applies the immutable flag via recheckFiles and
// logs; the notifier integration is wired in the daemon layer.
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

	// Note: we watch directories (not files) because inotify watch on a file is
	// lost when the file is renamed away. Watching the parent dir captures
	// create/write/remove/rename of the protected file within it.

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			// Only act on events for actual protected files.
			if !isProtectedPath(ev.Name, files) {
				continue
			}

			switch {
			case ev.Op&fsnotify.Chmod != 0:
				// chattr -i cleared the immutable flag; re-apply it.
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

// withPath returns a single-element slice of a path, for recheckFiles calls
// scoped to the affected file.
func withPath(path string) []string {
	return []string{path}
}
