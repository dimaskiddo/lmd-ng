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
		Short: "Install and Start LMD-NG as System Service",
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

			log.Info("LMD-NG service installed and started successfully.")
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

	return serviceCmd
}
