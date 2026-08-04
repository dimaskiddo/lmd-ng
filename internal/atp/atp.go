package atp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// Protector implements cross-platform active anti-tamper protection.
// On Linux: chattr +i + fanotify FAN_DENY + inotify detect.
// On macOS: chflags SF_IMMUTABLE + periodic recheck.
// On Windows: service DACL + exclusive file handle + SACL auditing.
type Protector struct {
	cfg *config.Config
	// alert broadcasts a high-priority tamper alert. Set by the daemon via
	// SetAlertFunc; nil means alerts are only logged.
	alert func(title, message string)
}

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

// Protect locks all critical files. Called once at daemon startup.
//
// Returns a control channel that the caller uses to drive the protection
// goroutines. Supported commands:
//
//	"unlock" — release all protections (for self-upgrade)
//	"lock" — re-apply all protections (after upgrade)
//	"shutdown" — stop all monitoring goroutines
func (p *Protector) Protect(ctx context.Context) (chan string, error) {
	// Runtime tamper indicator: if the running binary's inode was replaced
	// after start, flag it loudly. No embedded hash required.
	if selfExeDeleted() {
		const msg = "The running binary was replaced on disk while it is executing " +
			"(/proc/self/exe reports (deleted)). Investigate immediately — " +
			"this is a strong indication of tampering."
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

	log.Info("ATP: protecting files", "count", len(files))

	// Phase 1: Active blocking — set immutable/DACL on all protected files
	if err := p.applyProtection(files); err != nil {
		return nil, fmt.Errorf("ATP: failed to apply protection: %w", err)
	}

	log.Info("ATP: active protection applied", "file_count", len(files))

	// Phase 2: Start platform-specific monitor (fanotify listener, exclusive handles, etc.)
	control := make(chan string, 1)
	go p.startMonitor(ctx, files, control)

	// Phase 3: Periodic recheck — verify protections are still active
	go p.periodicRecheck(ctx, files, control)

	log.Info("ATP: protection active")
	return control, nil
}

// ReleaseAll releases all active protections on the given files.
// Called before self-upgrade so the binary can be replaced.
func (p *Protector) ReleaseAll(files []string) error {
	return p.removeProtection(files)
}

// protectedFiles derives the list of absolute file paths to protect.
// Categories are always-on (no config toggles). ClamAV DBs are protected
// only when scanner.clamav_enabled is true.
func (p *Protector) protectedFiles() []string {
	var files []string

	// Binary — always
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			files = append(files, resolved)
		} else {
			files = append(files, exe)
		}
	}

	// Config — always (all known locations)
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

	// LMD signatures — always
	filepath.WalkDir(p.cfg.App.SignaturesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})

	// TLS certs — always
	filepath.WalkDir(p.cfg.Server.TLS.CertsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})

	// ClamAV DBs — auto: only when clamav_enabled
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

	// Quarantine — always
	filepath.WalkDir(p.cfg.Quarantine.Path, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	})

	return files
}

// periodicRecheck periodically verifies that protections are still active.
// Detects and re-applies cleared flags/DACLs, logs tampering events.
// Recheck interval is hardcoded at 5 minutes — no config toggle.
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
