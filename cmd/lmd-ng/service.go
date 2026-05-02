package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/service"
)

func serviceCmd() *cobra.Command {
	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "LMD-NG Service Management",
		Long: `Manage LMD-NG Service Installation / Uninstallation.

Service install and uninstall operations require elevated privileges:
  - Linux / macOS : run with sudo or as root
  - Windows       : run from an Administrator command prompt`,
	}

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Install LMD-NG as System Service",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			if err := service.InstallService(cfg); err != nil {
				if errors.Is(err, service.ErrInsufficientPrivilege) {
					fmt.Fprintln(os.Stderr, "Error:", err)
					fmt.Fprintln(os.Stderr, "Hint: Re-run with 'sudo lmd-ng service install' (Linux/macOS) or from an elevated Administrator prompt (Windows).")
					os.Exit(1)
				}

				log.Error("Service installation failed", "error", err)
				os.Exit(1)
			}

			log.Info("LMD-NG service installed successfully.")
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "uninstall",
		Short: "Stop and Remove the LMD-NG from System Service",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			if err := service.UninstallService(cfg); err != nil {
				if errors.Is(err, service.ErrInsufficientPrivilege) {
					fmt.Fprintln(os.Stderr, "Error:", err)
					fmt.Fprintln(os.Stderr, "Hint: Re-run with 'sudo lmd-ng service uninstall' (Linux/macOS) or from an elevated Administrator prompt (Windows).")
					os.Exit(1)
				}

				log.Error("Service uninstallation failed", "error", err)
				os.Exit(1)
			}

			log.Info("LMD-NG service stopped and uninstalled successfully.")
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "start",
		Short: "Start LMD-NG System Service",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			if err := service.StartService(cfg); err != nil {
				if errors.Is(err, service.ErrInsufficientPrivilege) {
					fmt.Fprintln(os.Stderr, "Error:", err)
					fmt.Fprintln(os.Stderr, "Hint: Re-run with 'sudo lmd-ng service start' (Linux/macOS) or from an elevated Administrator prompt (Windows).")
					os.Exit(1)
				}

				log.Error("Service start failed", "error", err)
				os.Exit(1)
			}

			log.Info("LMD-NG service started successfully.")
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "stop",
		Short: "Stop LMD-NG System Service",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			if err := service.StopService(cfg); err != nil {
				if errors.Is(err, service.ErrInsufficientPrivilege) {
					fmt.Fprintln(os.Stderr, "Error:", err)
					fmt.Fprintln(os.Stderr, "Hint: Re-run with 'sudo lmd-ng service stop' (Linux/macOS) or from an elevated Administrator prompt (Windows).")
					os.Exit(1)
				}

				log.Error("Service stop failed", "error", err)
				os.Exit(1)
			}

			log.Info("LMD-NG service stopped successfully.")
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "restart",
		Short: "Restart LMD-NG System Service",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			if err := service.RestartService(cfg); err != nil {
				if errors.Is(err, service.ErrInsufficientPrivilege) {
					fmt.Fprintln(os.Stderr, "Error:", err)
					fmt.Fprintln(os.Stderr, "Hint: Re-run with 'sudo lmd-ng service restart' (Linux/macOS) or from an elevated Administrator prompt (Windows).")
					os.Exit(1)
				}

				log.Error("Service restart failed", "error", err)
				os.Exit(1)
			}

			log.Info("LMD-NG service restarted successfully.")
		},
	})

	return serviceCmd
}
