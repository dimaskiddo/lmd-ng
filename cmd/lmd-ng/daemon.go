package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/monitor"
	"github.com/dimaskiddo/lmd-ng/internal/notifier"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
	"github.com/dimaskiddo/lmd-ng/internal/scheduler"
	"github.com/dimaskiddo/lmd-ng/internal/updater"
)

// buildEngines creates the full set of signature engines from the current
// configuration. This function is used both at startup and during hot-reload.
func buildEngines(cfg *config.Config) ([]scanner.SignatureEngine, error) {
	lmdScanner, err := scanner.NewLMDSignatureScanner(cfg)
	if err != nil {
		return nil, err
	}
	engines := []scanner.SignatureEngine{lmdScanner}

	if cfg.Scanner.ClamAVEnabled {
		clamEngine, clamErr := scanner.NewClamAVSignatureEngine(cfg)
		if clamErr != nil {
			return nil, clamErr
		}

		engines = append(engines, clamEngine)
	}

	return engines, nil
}

// watchSignatures watches the signature directories for changes and triggers
// engine reload. This allows manual `lmd-ng update` executions to signal the
// running daemon to reload signatures.
func watchSignatures(ctx context.Context, cfg *config.Config, coordinator *scanner.ScanCoordinator) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Error("Failed to create signature watcher", "error", err)
		return
	}

	// Ensure directories exist before watching
	os.MkdirAll(cfg.App.SignaturesDir, 0755)
	if err := watcher.Add(cfg.App.SignaturesDir); err != nil {
		log.Warn("Failed to watch signatures directory", "path", cfg.App.SignaturesDir, "error", err)
	}

	if cfg.Scanner.ClamAVEnabled {
		clamDBPath := cfg.Scanner.ClamAVDBPath
		if clamDBPath == "" {
			clamDBPath = cfg.App.ClamAVDir
		}
		if clamDBPath != "" {
			os.MkdirAll(clamDBPath, 0755)
			if err := watcher.Add(clamDBPath); err != nil {
				log.Warn("Failed to watch ClamAV DB directory", "path", clamDBPath, "error", err)
			}
		}
	}

	go func() {
		defer watcher.Close()
		var reloadTimer *time.Timer

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Look for file changes (Write, Rename, Create)
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					// Ignore temporary files created during download
					if strings.HasSuffix(event.Name, ".tmp") {
						continue
					}

					// Debounce to avoid reloading multiple times for a single update
					if reloadTimer != nil {
						reloadTimer.Stop()
					}

					reloadTimer = time.AfterFunc(5*time.Second, func() {
						log.Info("Signature updates detected on disk, reloading engines...")
						if err := coordinator.ReloadEngines(); err != nil {
							log.Error("Failed to reload signature engines", "error", err)
						}
					})
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}

				log.Error("Signature watcher error", "error", err)

			case <-ctx.Done():
				if reloadTimer != nil {
					reloadTimer.Stop()
				}

				return
			}
		}
	}()
}

func daemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "LMD-NG Resident Monitoring (Daemon)",
		Run: func(cmd *cobra.Command, args []string) {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			cfg := cfgMgr.GetConfig()

			go cfgMgr.WatchConfig(ctx)

			engines, err := buildEngines(cfg)
			if err != nil {
				log.Error("Failed to create signature engines", "error", err)
				os.Exit(1)
			}

			walker, err := scanner.NewWalker(cfg)
			if err != nil {
				log.Error("Failed to create scanner walker", "error", err)
				os.Exit(1)
			}

			coordinator := scanner.NewScanCoordinator(cfg, walker, engines)

			// Set the engine factory so the coordinator can rebuild engines
			// when signatures are updated on disk.
			coordinator.EngineFactory = buildEngines

			var notifiers []notifier.Notifier
			if cfg.Notification.Email.Enabled {
				notifiers = append(notifiers, notifier.NewEmailNotifier(&cfg.Notification.Email))
			}

			if cfg.Notification.Telegram.Enabled {
				notifiers = append(notifiers, notifier.NewTelegramNotifier(&cfg.Notification.Telegram))
			}

			multiNotifier := notifier.NewMultiNotifier(notifiers...)

			mon, err := monitor.NewMonitor(cfg, coordinator, multiNotifier)
			if err != nil {
				log.Error("Failed to create monitor", "error", err)
				os.Exit(1)
			}

			go func() {
				if err := mon.Start(ctx); err != nil && err != context.Canceled {
					log.Error("Monitor error", "error", err)
				}
			}()

			updaterSvc := updater.NewUpdater(cfg)

			// Watch signature directories for changes (both internal and external updates)
			watchSignatures(ctx, cfg, coordinator)

			sched, err := scheduler.NewScheduler(cfg, coordinator, updaterSvc)
			if err != nil {
				log.Error("Failed to create scheduler", "error", err)
				os.Exit(1)
			}
			sched.Start(ctx)

			log.Info("LMD-NG Daemon started")
			<-ctx.Done()

			log.Info("LMD-NG Daemon shutting down...")

			mon.Stop()
			sched.Stop()
		},
	}
}
