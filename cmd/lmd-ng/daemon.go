package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/dbs"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/notifier"
	"github.com/dimaskiddo/lmd-ng/internal/rtp"
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
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "LMD-NG Daemon Services",
		Long: `Start LMD-NG daemon services.

Without a subcommand, starts both DBS (Database Signature Service) and RTP
(Real-Time Protector) in a single process for convenience.

Subcommands:
  dbs   Start only the Database Signature Service (server)
  rtp   Start only the Real-Time Protector (client)`,
		Run: func(cmd *cobra.Command, args []string) {
			// No subcommand: run both DBS + RTP in single process
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			cfg := cfgMgr.GetConfig()

			go handleConfigReload(ctx)

			// --- Start DBS server in background ---
			engines, err := buildEngines(cfg)
			if err != nil {
				log.Error("Failed to create signature engines", "error", err)
				os.Exit(1)
			}

			server, err := dbs.NewServer(cfg, engines)
			if err != nil {
				log.Error("Failed to create DBS server", "error", err)
				os.Exit(1)
			}

			server.EngineFactory = buildEngines

			// Start update scheduler for DBS
			updaterSvc := updater.NewUpdater(cfg)
			updateSched, err := scheduler.NewUpdateScheduler(cfg, updaterSvc, server)
			if err != nil {
				log.Error("Failed to create update scheduler", "error", err)
				os.Exit(1)
			}

			go updateSched.Start(ctx)

			go func() {
				if err := server.Serve(ctx); err != nil {
					log.Error("DBS server error", "error", err)
				}
			}()

			// Give DBS a moment to start listening
			time.Sleep(500 * time.Millisecond)

			// --- Start RTP client ---
			var notifiers []notifier.Notifier
			if cfg.Notification.Email.Enabled {
				notifiers = append(notifiers, notifier.NewEmailNotifier(&cfg.Notification.Email))
			}

			if cfg.Notification.Telegram.Enabled {
				notifiers = append(notifiers, notifier.NewTelegramNotifier(&cfg.Notification.Telegram))
			}

			multiNotifier := notifier.NewMultiNotifier(notifiers...)

			rtpSvc, err := rtp.NewRTP(cfg, multiNotifier)
			if err != nil {
				log.Error("Failed to create RTP", "error", err)
				os.Exit(1)
			}

			// Start scan scheduler for RTP
			dbsClient, clientErr := dbs.NewClient(cfg)
			if clientErr != nil {
				log.Error("Failed to create DBS client for scan scheduler", "error", clientErr)
				os.Exit(1)
			}

			scanSched, schedErr := scheduler.NewScanScheduler(cfg, dbsClient)
			if schedErr != nil {
				log.Error("Failed to create scan scheduler", "error", schedErr)
				os.Exit(1)
			}

			go scanSched.Start(ctx)

			go func() {
				if err := rtpSvc.Start(ctx); err != nil && err != context.Canceled {
					log.Error("RTP error", "error", err)
				}
			}()

			log.Info("LMD-NG Daemon started (DBS + RTP)")
			<-ctx.Done()

			log.Info("LMD-NG Daemon shutting down...")

			rtpSvc.Stop()
			scanSched.Stop()
			updateSched.Stop()
			server.Shutdown()
		},
	}

	cmd.AddCommand(dbsCmd())
	cmd.AddCommand(rtpCmd())

	return cmd
}

func dbsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dbs",
		Short: "Start the Database Signature Service (server)",
		Long: `Start the centralized Database Signature Service (DBS).

DBS loads all malware signature databases into memory once and listens for scan
requests from clients (RTP, on-demand scan) over an encrypted socket connection.
Signature reload is triggered via socket command from 'lmd-ng update'.`,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			cfg := cfgMgr.GetConfig()

			go handleConfigReload(ctx)

			engines, err := buildEngines(cfg)
			if err != nil {
				log.Error("Failed to create signature engines", "error", err)
				os.Exit(1)
			}

			server, err := dbs.NewServer(cfg, engines)
			if err != nil {
				log.Error("Failed to create DBS server", "error", err)
				os.Exit(1)
			}

			server.EngineFactory = buildEngines

			// Start update scheduler
			updaterSvc := updater.NewUpdater(cfg)
			updateSched, err := scheduler.NewUpdateScheduler(cfg, updaterSvc, server)
			if err != nil {
				log.Error("Failed to create update scheduler", "error", err)
				os.Exit(1)
			}

			go updateSched.Start(ctx)

			go func() {
				if err := server.Serve(ctx); err != nil {
					log.Error("DBS server error", "error", err)
				}
			}()

			log.Info("LMD-NG DBS (Database Signature Service) started")
			<-ctx.Done()

			log.Info("LMD-NG DBS shutting down...")

			updateSched.Stop()
			server.Shutdown()
		},
	}
}

func rtpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rtp",
		Short: "Start the Real-Time Protector (client)",
		Long: `Start the Real-Time Protector (RTP) client service.

RTP monitors file system events (FSEvents on macOS, fsnotify on Linux/Windows)
and streams modified files to the DBS server for signature matching. It handles
quarantine locally. The DBS server must be running before starting RTP.`,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			cfg := cfgMgr.GetConfig()

			go handleConfigReload(ctx)

			var notifiers []notifier.Notifier
			if cfg.Notification.Email.Enabled {
				notifiers = append(notifiers, notifier.NewEmailNotifier(&cfg.Notification.Email))
			}

			if cfg.Notification.Telegram.Enabled {
				notifiers = append(notifiers, notifier.NewTelegramNotifier(&cfg.Notification.Telegram))
			}

			multiNotifier := notifier.NewMultiNotifier(notifiers...)

			rtpSvc, err := rtp.NewRTP(cfg, multiNotifier)
			if err != nil {
				log.Error("Failed to create RTP", "error", err)
				os.Exit(1)
			}

			// Start scan scheduler
			dbsClient, clientErr := dbs.NewClient(cfg)
			if clientErr != nil {
				log.Error("Failed to create DBS client for scan scheduler", "error", clientErr)
				os.Exit(1)
			}

			scanSched, schedErr := scheduler.NewScanScheduler(cfg, dbsClient)
			if schedErr != nil {
				log.Error("Failed to create scan scheduler", "error", schedErr)
				os.Exit(1)
			}

			go scanSched.Start(ctx)

			go func() {
				if err := rtpSvc.Start(ctx); err != nil && err != context.Canceled {
					log.Error("RTP error", "error", err)
				}
			}()

			log.Info("LMD-NG RTP (Real-Time Protector) started")
			<-ctx.Done()

			log.Info("LMD-NG RTP shutting down...")

			rtpSvc.Stop()
			scanSched.Stop()
		},
	}
}


func handleConfigReload(ctx context.Context) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	for {
		select {
		case <-hup:
			log.Info("Received SIGHUP, reloading configuration...")
			if err := cfgMgr.ReloadConfig(); err != nil {
				log.Error("Failed to reload configuration", "error", err)
			}

		case <-ctx.Done():
			return
		}
	}
}
