package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/service"
	"github.com/dimaskiddo/lmd-ng/internal/upgrade"
)

func upgradeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upgrade",
		Short: "Upgrade LMD-NG binary to latest release",
		Long: `Upgrade the LMD-NG binary by downloading the latest release from GitHub,
stopping services, replacing the binary, and restarting services.

Services are managed automatically:
  - If services are installed (via 'lmd-ng service install'), they are
    stopped, binary replaced, and restarted.
  - If services are not installed, the binary is replaced on disk and
    a warning is printed to restart any running daemon process manually.`,
		Run: runUpgrade,
	}

	cmd.Flags().BoolP("force", "f", false, "Force upgrade even if already latest version")

	return cmd
}

func runUpgrade(cmd *cobra.Command, args []string) {
	force, _ := cmd.Flags().GetBool("force")

	cfg := cfgMgr.GetConfig()
	ctx := context.Background()

	currentVer := version

	fmt.Println("LMD-NG Upgrade")
	fmt.Println(strings.Repeat("━", 62))
	fmt.Println()

	// --- Current version ---
	fmt.Printf("  Current version: %s\n", currentVer)
	fmt.Println()

	// --- Query latest version ---
	fmt.Println("  Checking for latest version...")

	u := upgrade.NewUpgrader(cfg)

	latestTag, err := u.LatestVersion(ctx)
	if err != nil {
		log.Error("Failed to check for latest version", "error", err)
		os.Exit(1)
	}

	latestVer := strings.TrimPrefix(latestTag, "v")
	fmt.Printf("  Latest version:  %s\n", latestTag)
	fmt.Println()

	// --- Version comparison ---
	if currentVer == latestVer && !force {
		fmt.Println("  Already up-to-date. Use --force to reinstall.")
		return
	}

	if force && currentVer == latestVer {
		fmt.Println("  Force upgrade enabled. Reinstalling current version.")
	}

	fmt.Printf("  Upgrading from %s to %s\n", currentVer, latestTag)
	fmt.Println()

	// --- Download release ---
	fmt.Println("  Downloading release...")

	binaryPath, cleanup, err := u.DownloadRelease(ctx, latestTag, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		log.Error("Failed to download release", "error", err)
		os.Exit(1)
	}
	defer cleanup()

	fmt.Println("  Release downloaded successfully")
	fmt.Println()

	// --- Detect services ---
	dbsInstalled := service.IsServiceInstalled(service.ComponentDBS)
	rtpInstalled := service.IsServiceInstalled(service.ComponentRTP)

	// --- Stop services (if installed) ---
	if rtpInstalled || dbsInstalled {
		fmt.Println("  Stopping services...")

		if rtpInstalled {
			if err := service.StopService(cfg, service.ComponentRTP); err != nil {
				log.Warn("Failed to stop RTP service (continuing)", "error", err)
			} else {
				fmt.Println("    RTP stopped")
			}
		}

		if dbsInstalled {
			if err := service.StopService(cfg, service.ComponentDBS); err != nil {
				log.Warn("Failed to stop DBS service (continuing)", "error", err)
			} else {
				fmt.Println("    DBS stopped")
			}
		}

		// Allow time for services to fully exit
		time.Sleep(1 * time.Second)
		fmt.Println()
	}

	// --- Replace binary ---
	fmt.Println("  Replacing binary...")

	exePath, err := os.Executable()
	if err != nil {
		log.Error("Failed to get executable path", "error", err)
		os.Exit(1)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		log.Error("Failed to resolve executable symlink", "error", err)
		os.Exit(1)
	}

	// Build service names list for Windows batch trampoline
	var serviceNames []string
	if dbsInstalled {
		serviceNames = append(serviceNames, "lmd-ng-dbs")
	}
	if rtpInstalled {
		serviceNames = append(serviceNames, "lmd-ng-rtp")
	}

	if err := upgrade.ReplaceBinary(exePath, binaryPath, serviceNames); err != nil {
		log.Error("Failed to replace binary", "error", err)
		os.Exit(1)
	}

	fmt.Println("    Binary replaced")
	fmt.Println()

	// --- Start services (if they were installed) ---
	if rtpInstalled || dbsInstalled {
		fmt.Println("  Starting services...")

		if dbsInstalled {
			if err := service.StartService(cfg, service.ComponentDBS); err != nil {
				log.Warn("Failed to start DBS service", "error", err)
			} else {
				fmt.Println("    DBS started")
			}
		}

		if rtpInstalled {
			// Give DBS a moment to start before RTP connects
			time.Sleep(1 * time.Second)

			if err := service.StartService(cfg, service.ComponentRTP); err != nil {
				log.Warn("Failed to start RTP service", "error", err)
			} else {
				fmt.Println("    RTP started")
			}
		}

		fmt.Println()
	} else {
		fmt.Println("  Services not installed. Restart daemon manually if running:")
		fmt.Println("    pkill lmd-ng && lmd-ng daemon")
		fmt.Println()
	}

	// --- Done ---
	backupPath := exePath + ".old"
	fmt.Printf("  Upgrade complete: %s\n", exePath)
	fmt.Printf("  Old binary saved: %s\n", backupPath)
}
