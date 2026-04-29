package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

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

			emailNotifier := notifier.NewEmailNotifier(&cfg.Notification)

			mon, err := monitor.NewMonitor(cfg, coordinator, emailNotifier)
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

			// Wire the reload callback: after signatures update, reload engines.
			updaterSvc.OnSignaturesUpdated = func() {
				if err := coordinator.ReloadEngines(); err != nil {
					log.Error("Failed to reload signature engines after update", "error", err)
				}
			}

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
