package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/service"
)

func serviceCmd() *cobra.Command {
	serviceCmd := &cobra.Command{
		Use:   "service",
		Short: "LMD-NG Service Management",
	}

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Install LMD-NG to Service Manager",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			if err := service.InstallService(cfg); err != nil {
				log.Error("Service installation failed", "error", err)
				os.Exit(1)
			}

			log.Info("LMD-NG service installed successfully.")
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall LMD-NG from Service Manager",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			if err := service.UninstallService(cfg); err != nil {
				log.Error("Service uninstallation failed", "error", err)
				os.Exit(1)
			}

			log.Info("LMD-NG service uninstalled successfully.")
		},
	})

	return serviceCmd
}
