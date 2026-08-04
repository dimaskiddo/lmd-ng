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
  - Windows       : run from an Administrator command prompt

Components:
  atp   Anti-Tamper Protection (file locking)
  dbs   Database Signature Service (server)
  rtp   Real-Time Protector (client)

If no component is specified, the command acts on all three components.
For install/start: ATP, then DBS, then RTP.
For stop/uninstall: RTP, then DBS, then ATP.`,
	}

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "install [atp|dbs|rtp]",
		Short: "Install LMD-NG as System Service",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			components := resolveComponents(args, false) // install order: dbs first

			// Auto-migrate: uninstall legacy monolithic service if it exists
			if err := service.UninstallLegacyService(); err != nil {
				// Non-fatal — legacy service may not exist
				log.Debug("Legacy service migration check", "result", err)
			}

			for _, comp := range components {
				if err := service.InstallService(cfg, comp); err != nil {
					handleServiceError(err, "install", comp)
					return
				}

				log.Info("Service installed successfully", "component", comp)
			}
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "uninstall [atp|dbs|rtp]",
		Short: "Stop and Remove the LMD-NG from System Service",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			components := resolveComponents(args, true) // uninstall order: rtp first

			// Auto-migrate: uninstall legacy monolithic service if it exists
			if err := service.UninstallLegacyService(); err != nil {
				// Non-fatal — legacy service may not exist
				log.Debug("Legacy service migration check", "result", err)
			}

			for _, comp := range components {
				if err := service.UninstallService(cfg, comp); err != nil {
					handleServiceError(err, "uninstall", comp)
					return
				}

				log.Info("Service uninstalled successfully", "component", comp)
			}
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "start [atp|dbs|rtp]",
		Short: "Start LMD-NG System Service",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			components := resolveComponents(args, false) // start order: dbs first

			for _, comp := range components {
				if err := service.StartService(cfg, comp); err != nil {
					handleServiceError(err, "start", comp)
					return
				}

				log.Info("Service started successfully", "component", comp)
			}
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "stop [atp|dbs|rtp]",
		Short: "Stop LMD-NG System Service",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			components := resolveComponents(args, true) // stop order: rtp first

			for _, comp := range components {
				if err := service.StopService(cfg, comp); err != nil {
					handleServiceError(err, "stop", comp)
					return
				}

				log.Info("Service stopped successfully", "component", comp)
			}
		},
	})

	serviceCmd.AddCommand(&cobra.Command{
		Use:   "restart [atp|dbs|rtp]",
		Short: "Restart LMD-NG System Service",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cfg := cfgMgr.GetConfig()
			components := resolveComponents(args, false) // restart order: dbs first

			for _, comp := range components {
				if err := service.RestartService(cfg, comp); err != nil {
					handleServiceError(err, "restart", comp)
					return
				}

				log.Info("Service restarted successfully", "component", comp)
			}
		},
	})

	return serviceCmd
}

// resolveComponents returns the list of components to operate on based on the
// CLI args. If no component is specified, returns all components in the
// appropriate order.
//
// install/start order: ATP → DBS → RTP — ATP locks files first so protected
// files are never writable while services operate on them.
//
// stop/uninstall order (reverseOrder=true): RTP → DBS → ATP — RTP (client)
// stops before DBS (server), and ATP releases its file locks last so files
// remain protected for as long as any LMD-NG service is running.
func resolveComponents(args []string, reverseOrder bool) []service.Component {
	if len(args) == 1 {
		return []service.Component{service.Component(args[0])}
	}

	if reverseOrder {
		return []service.Component{service.ComponentRTP, service.ComponentDBS, service.ComponentATP}
	}

	return []service.Component{service.ComponentATP, service.ComponentDBS, service.ComponentRTP}
}

// handleServiceError handles service management errors with appropriate
// messaging for privilege issues.
func handleServiceError(err error, action string, comp service.Component) {
	if errors.Is(err, service.ErrInsufficientPrivilege) {
		fmt.Fprintln(os.Stderr, "Error:", err)
		fmt.Fprintf(os.Stderr, "Hint: Re-run with 'sudo lmd-ng service %s %s' (Linux/macOS) or from an elevated Administrator prompt (Windows).\n", action, comp)
		os.Exit(1)
	}

	log.Error("Service operation failed", "action", action, "component", comp, "error", err)
	os.Exit(1)
}
