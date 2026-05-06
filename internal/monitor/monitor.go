package monitor

import (
	"context"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/notifier"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
)

// ScanFunc is a function that scans a single file and returns the results and
// whether the file was quarantined. This abstraction decouples the monitor from
// the ScanCoordinator, allowing both local (monolithic) and remote (DBS client)
// scan implementations.
type ScanFunc func(ctx context.Context, filePath string) ([]*scanner.ScanResult, bool)

// Monitor monitors file system events and triggers scans.
// The concrete implementation is platform-specific:
//   - macOS: uses FSEvents (no file descriptor limits)
//   - Linux/Windows: uses fsnotify (inotify / ReadDirectoryChangesW)
type Monitor struct {
	cfg      *config.Config
	scanFunc ScanFunc
	notifier notifier.Notifier
	impl     monitorImpl
}

// monitorImpl is the platform-specific monitor backend.
type monitorImpl interface {
	// Start begins the event loop. Blocks until ctx is cancelled.
	Start(ctx context.Context) error
	// Stop tears down the watcher and releases resources.
	Stop() error
}

// NewMonitor creates and initializes a new file system monitor.
// The scanFunc callback is invoked for each file event that requires scanning.
func NewMonitor(cfg *config.Config, scanFunc ScanFunc, n notifier.Notifier) (*Monitor, error) {
	m := &Monitor{
		cfg:      cfg,
		scanFunc: scanFunc,
		notifier: n,
	}

	impl, err := newPlatformMonitor(m)
	if err != nil {
		return nil, err
	}

	m.impl = impl
	return m, nil
}

// Start begins monitoring file system events.
func (m *Monitor) Start(ctx context.Context) error {
	return m.impl.Start(ctx)
}

// Stop stops the file system monitor.
func (m *Monitor) Stop() error {
	return m.impl.Stop()
}
