package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/updater"
)

var (
	cfgFile string
	cfgMgr  *config.Manager
)

func init() {
	var err error

	cfgMgr, err = config.NewConfigManager(cfgFile)
	if err != nil {
		slog.Default().Error("failed to initialize config manager", "error", err)
		os.Exit(1)
	}

	// Initialize the logger using the loaded configuration
	log.InitLogger(&log.Config{
		Level:      cfgMgr.GetConfig().Logging.Level,
		Output:     cfgMgr.GetConfig().Logging.Output,
		FilePath:   cfgMgr.GetConfig().Logging.FilePath,
		MaxSize:    cfgMgr.GetConfig().Logging.MaxSize,
		MaxBackups: cfgMgr.GetConfig().Logging.MaxBackups,
		MaxAge:     cfgMgr.GetConfig().Logging.MaxAge,
		Compress:   cfgMgr.GetConfig().Logging.Compress,
	})

	rootCmd := &cobra.Command{
		Use:   "lmd-ng",
		Short: "Linux Malware Detect Next Generation (LMD-NG)",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cfgFile != "" {
				cfgMgr.Viper.SetConfigFile(cfgFile)
				if err := cfgMgr.Viper.ReadInConfig(); err != nil {
					if _, ok := err.(viper.ConfigFileNotFoundError); ok {
						log.Warn("Config file not found at '%s', using default and compiled-in config values.", cfgFile)
					} else {
						return fmt.Errorf("failed to read config file '%s': %w", cfgFile, err)
					}
				}

				if err := cfgMgr.Viper.Unmarshal(cfgMgr.Config); err != nil {
					return fmt.Errorf("failed to unmarshal config: %w", err)
				}
			}

			cfg := cfgMgr.GetConfig()

			// Calculate and set CPU limit
			numCPU := runtime.NumCPU()
			cpuLimit := cfg.Scanner.CPULimit

			if cpuLimit <= 0 {
				// Default to half of the total cores if not specified or set to 0
				cpuLimit = numCPU / 2
			} else if cpuLimit > numCPU {
				cpuLimit = numCPU
			}

			// Ensure at least 1 core is used
			if cpuLimit < 1 {
				cpuLimit = 1
			}

			// Strictly limit the Go runtime to the calculated CPU cores
			runtime.GOMAXPROCS(cpuLimit)
			
			// Update the config so other parts of the app can use the actual limit
			cfg.Scanner.CPULimit = cpuLimit
			
			log.Debug("CPU limit configured", "cpu_limit", cpuLimit, "total_cores", numCPU)

			// Auto-create all required directories on every startup
			if err := config.EnsureDirectories(cfg); err != nil {
				return fmt.Errorf("failed to create application directories: %w", err)
			}

			// For commands that need signatures (scan, daemon), force
			// initial update if no signature databases exist yet.
			cmdName := cmd.Name()
			if cmdName == "scan" || cmdName == "daemon" {
				if !config.HasSignatures(cfg) {
					log.Info("No signature databases found, performing initial update...")

					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					updaterSvc := updater.NewUpdater(cfg)
					if err := updaterSvc.Update(ctx); err != nil {
						log.Error("Initial signature update failed", "error", err)
						return fmt.Errorf("initial signature update failed: %w", err)
					}

					log.Info("Initial signature update completed successfully")
				}
			}

			return nil
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "path to configuration file (default is config.yaml in current dir, /etc/lmd-ng/, /usr/local/etc/lmd-ng/, or /usr/local/lmd-ng/)")

	rootCmd.AddCommand(daemonCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(updateCmd())
	rootCmd.AddCommand(serviceCmd())
	rootCmd.AddCommand(quarantineCmd())
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		slog.Default().Error("CLI execution failed", "error", err)
		os.Exit(1)
	}
}

func main() {
	// main is now empty as init() handles CLI execution
}
