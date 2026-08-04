package atp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// Protector implements cross-platform active anti-tamper protection.
type Protector struct {
	cfg   *config.Config
	files []string
	// alert broadcasts a tamper alert. Set by the daemon via SetAlertFunc.
	alert func(title, message string)
}

// pidFileName is the PID file name under the app base path, used by status
// to confirm ATP is running (immutable flags alone survive a crash).
const pidFileName = "lmd-ng-atp.pid"

// SetAlertFunc registers a callback used to broadcast tamper alerts to
// configured notifiers. The daemon wires this to MultiNotifier.SendAlert.
func (p *Protector) SetAlertFunc(fn func(title, message string)) {
	p.alert = fn
}

// NewProtector creates a new ATP Protector. ATP is always active —
// there is no config toggle to disable it.
func NewProtector(cfg *config.Config) *Protector {
	return &Protector{cfg: cfg}
}

// Protect locks all critical files. Returns a control channel that drives
// the protection goroutines ("unlock", "lock", "shutdown").
func (p *Protector) Protect(ctx context.Context) (chan string, error) {
	if selfExeDeleted() {
		const msg = "The running binary was replaced on disk " +
			"(/proc/self/exe reports (deleted)). Investigate immediately."
		log.Error("ATP: TAMPER DETECTED — running binary inode was replaced", "detail", msg)
		if p.alert != nil {
			p.alert("Tamper Detected", msg)
		}
	}

	files := p.protectedFiles()
	if len(files) == 0 {
		log.Warn("ATP: no protected files found — binary path may be unresolvable")
		ch := make(chan string)
		close(ch)
		return ch, nil
	}
	p.files = files

	// Clear stale immutable flags from a previous crashed session before
	// applying fresh protection. Non-fatal: flags may not exist or the
	// filesystem may not support them.
	if err := p.removeProtection(files); err != nil {
		log.Warn("ATP: failed to clear stale protection flags", "error", err)
	}

	log.Info("ATP: protecting files", "count", len(files))

	if err := p.applyProtection(files); err != nil {
		return nil, fmt.Errorf("ATP: failed to apply protection: %w", err)
	}

	log.Info("ATP: active protection applied", "file_count", len(files))

	control := make(chan string, 1)
	go p.startMonitor(ctx, files, control)
	go p.periodicRecheck(ctx, files, control)

	if err := p.writePID(); err != nil {
		log.Warn("ATP: failed to write PID file", "error", err)
	}

	log.Info("ATP: protection active")
	return control, nil
}

// ReleaseAll releases all active protections on the given files.
// Called before self-upgrade so the binary can be replaced.
func (p *Protector) ReleaseAll(files []string) error {
	return p.removeProtection(files)
}

// ProtectedFiles returns the files ATP currently protects. Empty before
// Protect is called. Used by shutdown to clear immutable flags.
func (p *Protector) ProtectedFiles() []string {
	return p.files
}

// Done stops ATP cleanly: clears immutable flags and removes the PID file.
func (p *Protector) Done() {
	if len(p.files) > 0 {
		if err := p.removeProtection(p.files); err != nil {
			log.Warn("ATP: failed to clear protection flags on shutdown", "error", err)
		}
	}
	p.removePID()
}

// writePID writes the current process ID to the PID file.
func (p *Protector) writePID() error {
	pidFile := filepath.Join(p.cfg.App.BasePath, pidFileName)
	return os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o644)
}

// removePID removes the PID file if present.
func (p *Protector) removePID() {
	pidFile := filepath.Join(p.cfg.App.BasePath, pidFileName)
	os.Remove(pidFile)
}

// protectedFiles derives the absolute paths to protect. ClamAV DBs are
// included only when scanner.clamav_enabled is true.
func (p *Protector) protectedFiles() []string {
	var files []string

	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			files = append(files, resolved)
		} else {
			files = append(files, exe)
		}
	}

	for _, cf := range []string{
		filepath.Join(p.cfg.App.BasePath, "config.yaml"),
		"/etc/lmd-ng/config.yaml",
		"/usr/local/etc/lmd-ng/config.yaml",
		"/usr/local/lmd-ng/config.yaml",
	} {
		if _, err := os.Stat(cf); err == nil {
			files = append(files, cf)
		}
	}

	filepath.WalkDir(p.cfg.App.SignaturesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})

	filepath.WalkDir(p.cfg.Server.TLS.CertsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})

	if p.cfg.Scanner.ClamAVEnabled {
		clamDir := p.cfg.Scanner.ClamAVDBPath
		if clamDir == "" {
			clamDir = p.cfg.App.ClamAVDir
		}
		filepath.WalkDir(clamDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if filepath.Ext(path) == ".cvd" {
				files = append(files, path)
			}
			return nil
		})
	}

	filepath.WalkDir(p.cfg.Quarantine.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})

	return files
}

// periodicRecheck verifies protections are still active and re-applies cleared ones.
func (p *Protector) periodicRecheck(ctx context.Context, files []string, control <-chan string) {
	const recheckInterval = 5 * time.Minute
	ticker := time.NewTicker(recheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-control:
			if cmd == "shutdown" {
				return
			}
		case <-ticker.C:
			p.recheckFiles(files)
		}
	}
}
