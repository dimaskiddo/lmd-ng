package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	kservice "github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/atp"
	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/dbs"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/notifier"
	"github.com/dimaskiddo/lmd-ng/internal/rtp"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
	"github.com/dimaskiddo/lmd-ng/internal/scheduler"
	"github.com/dimaskiddo/lmd-ng/internal/service"
	"github.com/dimaskiddo/lmd-ng/internal/updater"
)

// buildEngines creates the full set of signature engines from the current
// configuration. This function is used both at startup and during hot-reload.
func buildEngines(cfg *config.Config) ([]scanner.SignatureEngine, error) {
	lmdScanner, err := scanner.NewLMDSignatureScanner(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create LMD signature scanner: %w", err)
	}
	engines := []scanner.SignatureEngine{lmdScanner}

	if cfg.Scanner.ClamAVEnabled {
		clamEngine, clamErr := scanner.NewClamAVSignatureEngine(cfg)
		if clamErr != nil {
			log.Warn("Failed to create ClamAV engine, continuing without it", "error", clamErr)
		} else {
			engines = append(engines, clamEngine)
		}
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

			// Combined daemon uses the configured log path unless overridden.
			lp, _ := cmd.Flags().GetString("log-file")
			if lp == "" {
				lp = cfg.Logging.FilePath
			}
			log.InitLoggerWithPath(lp, logConfig(cfg.Logging))

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConfigReload(ctx)
			}()

			var atpControl chan string
			protector := atp.NewProtector(cfg)
			protector.SetAlertFunc(func(title, msg string) {
				if err := buildMultiNotifier(cfg).SendAlert(ctx, title, msg); err != nil {
					log.Warn("Failed to send tamper alert", "error", err)
				}
			})
			control, atpErr := protector.Protect(ctx)
			if atpErr != nil {
				log.Error("ATP: failed to start", "error", atpErr)
				log.Warn("ATP: continuing without active tamper protection")
			} else {
				atpControl = control
				log.Info("ATP: active tamper protection enabled")
			}

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

			wg.Add(1)
			go func() {
				defer wg.Done()
				updateSched.Start(ctx)
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := server.Serve(ctx); err != nil {
					log.Error("DBS server error", "error", err)
				}
			}()

			var notifiers []notifier.Notifier
			if cfg.Notification.Email.Enabled {
				notifiers = append(notifiers, notifier.NewEmailNotifier(&cfg.Notification.Email))
			}

			if cfg.Notification.Telegram.Enabled {
				notifiers = append(notifiers, notifier.NewTelegramNotifier(&cfg.Notification.Telegram))
			}

			if cfg.Notification.Discord.Enabled {
				notifiers = append(notifiers, notifier.NewDiscordNotifier(&cfg.Notification.Discord))
			}

			if cfg.Notification.Slack.Enabled {
				notifiers = append(notifiers, notifier.NewSlackNotifier(&cfg.Notification.Slack))
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

			wg.Add(1)
			go func() {
				defer wg.Done()
				scanSched.Start(ctx)
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
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

			// Shut down ATP last so files stay protected until services stop.
			if atpControl != nil {
				atpControl <- "shutdown"
			}
			wg.Wait()
		},
	}

	cmd.Flags().String("log-file", "", "Log file path (default: config logging.filepath)")

	cmd.AddCommand(dbsCmd())
	cmd.AddCommand(rtpCmd())
	cmd.AddCommand(atpCmd())

	return cmd
}

func dbsCmd() *cobra.Command {
	cmd := &cobra.Command{
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

			// DBS uses its own log file (default <logs_dir>/lmd-ng-dbs.log).
			lp, _ := cmd.Flags().GetString("log-file")
			if lp == "" {
				lp = defaultLogFile(cfg, "dbs")
			}
			log.InitLoggerWithPath(lp, logConfig(cfg.Logging))

			// When run as an OS service, fail if ATP is not running.
			if svcMode, _ := cmd.Flags().GetBool("service"); svcMode {
				if err := verifyDependencies(cfg, service.ComponentDBS); err != nil {
					log.Error("DBS dependency check failed", "error", err)
					os.Exit(1)
				}
			}

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConfigReload(ctx)
			}()

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

			wg.Add(1)
			go func() {
				defer wg.Done()
				updateSched.Start(ctx)
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := server.Serve(ctx); err != nil {
					log.Error("DBS server error", "error", err)
				}
			}()

			log.Info("LMD-NG DBS (Database Signature Service) started")
			<-ctx.Done()

			log.Info("LMD-NG DBS shutting down...")

			updateSched.Stop()
			server.Shutdown()
			wg.Wait()
		},
	}

	cmd.Flags().String("log-file", "", "Log file path (default: <logs_dir>/lmd-ng-dbs.log)")
	cmd.Flags().Bool("service", false, "Running as OS service (internal)")

	return cmd
}

func rtpCmd() *cobra.Command {
	cmd := &cobra.Command{
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

			// RTP uses its own log file (default <logs_dir>/lmd-ng-rtp.log).
			lp, _ := cmd.Flags().GetString("log-file")
			if lp == "" {
				lp = defaultLogFile(cfg, "rtp")
			}
			log.InitLoggerWithPath(lp, logConfig(cfg.Logging))

			// When run as an OS service, fail if ATP or DBS is not running.
			if svcMode, _ := cmd.Flags().GetBool("service"); svcMode {
				if err := verifyDependencies(cfg, service.ComponentRTP); err != nil {
					log.Error("RTP dependency check failed", "error", err)
					os.Exit(1)
				}
			}

			var wg sync.WaitGroup

			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConfigReload(ctx)
			}()

			var notifiers []notifier.Notifier
			if cfg.Notification.Email.Enabled {
				notifiers = append(notifiers, notifier.NewEmailNotifier(&cfg.Notification.Email))
			}

			if cfg.Notification.Telegram.Enabled {
				notifiers = append(notifiers, notifier.NewTelegramNotifier(&cfg.Notification.Telegram))
			}

			if cfg.Notification.Discord.Enabled {
				notifiers = append(notifiers, notifier.NewDiscordNotifier(&cfg.Notification.Discord))
			}

			if cfg.Notification.Slack.Enabled {
				notifiers = append(notifiers, notifier.NewSlackNotifier(&cfg.Notification.Slack))
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

			wg.Add(1)
			go func() {
				defer wg.Done()
				scanSched.Start(ctx)
			}()

			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := rtpSvc.Start(ctx); err != nil && err != context.Canceled {
					log.Error("RTP error", "error", err)
				}
			}()

			log.Info("LMD-NG RTP (Real-Time Protector) started")
			<-ctx.Done()

			log.Info("LMD-NG RTP shutting down...")

			rtpSvc.Stop()
			scanSched.Stop()
			wg.Wait()
		},
	}

	cmd.Flags().String("log-file", "", "Log file path (default: <logs_dir>/lmd-ng-rtp.log)")
	cmd.Flags().Bool("service", false, "Running as OS service (internal)")

	return cmd
}

func atpCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "atp",
		Short: "Start the Anti-Tamper Protection daemon",
		Long: `Start the Anti-Tamper Protection (ATP) daemon.

ATP locks LMD-NG's critical files against modification/deletion by malware.
On Linux: chattr +i immutable flags + fanotify FAN_DENY permission listener.
On macOS: chflags SF_IMMUTABLE. On Windows: deny-write DACL + exclusive handles.
Runs standalone or alongside DBS and RTP as part of 'lmd-ng daemon'.`,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			cfg := cfgMgr.GetConfig()

			// ATP uses its own log file (default <logs_dir>/lmd-ng-atp.log).
			lp, _ := cmd.Flags().GetString("log-file")
			if lp == "" {
				lp = defaultLogFile(cfg, "atp")
			}
			log.InitLoggerWithPath(lp, logConfig(cfg.Logging))

			// When run as an OS service, verify ATP (no dependencies).
			if svcMode, _ := cmd.Flags().GetBool("service"); svcMode {
				if err := verifyDependencies(cfg, service.ComponentATP); err != nil {
					log.Error("ATP dependency check failed", "error", err)
					os.Exit(1)
				}
			}

			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				handleConfigReload(ctx)
			}()

			protector := atp.NewProtector(cfg)
			protector.SetAlertFunc(func(title, msg string) {
				if err := buildMultiNotifier(cfg).SendAlert(ctx, title, msg); err != nil {
					log.Warn("Failed to send tamper alert", "error", err)
				}
			})
			controlCh, err := protector.Protect(ctx)
			if err != nil {
				log.Error("ATP: failed to start protection", "error", err)
				os.Exit(1)
			}

			log.Info("LMD-NG ATP (Anti-Tamper Protection) started")
			<-ctx.Done()

			log.Info("LMD-NG ATP shutting down...")
			if controlCh != nil {
				controlCh <- "shutdown"
			}
			wg.Wait()
		},
	}

	cmd.Flags().String("log-file", "", "Log file path (default: <logs_dir>/lmd-ng-atp.log)")
	cmd.Flags().Bool("service", false, "Running as OS service (internal)")

	return cmd
}

// defaultLogFile returns the default per-component log file path under the
// configured logs directory (e.g. <logs_dir>/lmd-ng-dbs.log).
func defaultLogFile(cfg *config.Config, component string) string {
	return filepath.Join(cfg.App.LogsDir, "lmd-ng-"+component+".log")
}

// verifyDependencies checks that all required services for a component are
// running before the component starts. Returns nil if satisfied, or an error
// describing the missing dependency. Only enforced when running as an OS
// service (--service), where components run in separate processes.
func verifyDependencies(cfg *config.Config, comp service.Component) error {
	required := service.Dependencies[comp]
	if len(required) == 0 {
		return nil
	}

	for _, dep := range required {
		status, err := service.StatusService(cfg, dep)
		if err != nil {
			return fmt.Errorf("cannot verify required service %q: %w", dep, err)
		}
		if status == nil || *status != kservice.StatusRunning {
			return fmt.Errorf("required service %q is not running (status: %s)", dep, statusName(status))
		}
	}

	return nil
}

// statusName formats a kservice status for error messages, defaulting to
// "unknown" when the status is nil.
func statusName(status *kservice.Status) string {
	if status == nil {
		return "unknown"
	}
	switch *status {
	case kservice.StatusRunning:
		return "running"
	case kservice.StatusStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// buildMultiNotifier constructs a MultiNotifier from the current config.
func buildMultiNotifier(cfg *config.Config) *notifier.MultiNotifier {
	var notifiers []notifier.Notifier
	if cfg.Notification.Email.Enabled {
		notifiers = append(notifiers, notifier.NewEmailNotifier(&cfg.Notification.Email))
	}
	if cfg.Notification.Telegram.Enabled {
		notifiers = append(notifiers, notifier.NewTelegramNotifier(&cfg.Notification.Telegram))
	}
	if cfg.Notification.Discord.Enabled {
		notifiers = append(notifiers, notifier.NewDiscordNotifier(&cfg.Notification.Discord))
	}
	if cfg.Notification.Slack.Enabled {
		notifiers = append(notifiers, notifier.NewSlackNotifier(&cfg.Notification.Slack))
	}
	return notifier.NewMultiNotifier(notifiers...)
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
