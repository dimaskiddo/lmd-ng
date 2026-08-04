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
	// Show commit only when both look like real SHAs (dev builds show version only)
	commitSuffix := ""
	if commit != "" && commit != "none" && isHexSHA(commit) {
		commitSuffix = fmt.Sprintf(" (%s)", commit)
	}
	fmt.Printf("  Current version: %s%s\n", currentVer, commitSuffix)
	fmt.Println()

	// --- Query latest version ---
	fmt.Println("  Checking for latest version...")

	u := upgrade.NewUpgrader(cfg)

	latestTag, latestCommitish, err := u.LatestVersion(ctx)
	if err != nil {
		log.Error("Failed to check for latest version", "error", err)
		os.Exit(1)
	}

	// Strip v prefix for consistent display (GitHub returns "v0.2.0", local has "0.2.0")
	latestVer := strings.TrimPrefix(latestTag, "v")
	latestShortCommit := latestCommitish
	if len(latestShortCommit) > 7 {
		latestShortCommit = latestShortCommit[:7]
	}
	latestDisplay := latestVer
	if latestShortCommit != "" && isHexSHA(latestShortCommit) {
		latestDisplay = latestVer + " (" + latestShortCommit + ")"
	}
	fmt.Printf("  Latest version:  %s\n", latestDisplay)
	fmt.Println()

	// --- Version + commit comparison ---
	if currentVer == latestVer && !force {
		if sameCommit(commit, latestCommitish) {
			fmt.Println("  Already up-to-date. Use --force to reinstall.")
			return
		}
		fmt.Printf("  Same version tag, but newer commit available (%s → %s).\n", commit, latestShortCommit)
	}

	if force && currentVer == latestVer {
		if sameCommit(commit, latestCommitish) {
			fmt.Println("  Force upgrade enabled. Reinstalling current version.")
		}
	}

	commitNote := ""
	if isHexSHA(latestShortCommit) {
		commitNote = " (" + latestShortCommit + ")"
	}
	fmt.Printf("  Upgrading from %s (%s) to %s%s\n", currentVer, commit, latestVer, commitNote)
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
	atpInstalled := service.IsServiceInstalled(service.ComponentATP)
	dbsInstalled := service.IsServiceInstalled(service.ComponentDBS)
	rtpInstalled := service.IsServiceInstalled(service.ComponentRTP)

	// --- Stop services (if installed) ---
	// Order: RTP → DBS → ATP. ATP releases its file locks last so protected
	// files stay immutable for as long as any LMD-NG service is running. It
	// must be stopped before the binary replacement so the immutable flag on
	// the running executable can be cleared.
	if atpInstalled || dbsInstalled || rtpInstalled {
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

		if atpInstalled {
			fmt.Println("    Releasing ATP file locks...")
			if err := service.StopService(cfg, service.ComponentATP); err != nil {
				log.Warn("Failed to stop ATP service (continuing)", "error", err)
			} else {
				fmt.Println("    ATP stopped")
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
	// Order: ATP → DBS → RTP. ATP locks files first, then DBS reads
	// signatures, then RTP connects.
	if atpInstalled || dbsInstalled || rtpInstalled {
		fmt.Println("  Starting services...")

		if atpInstalled {
			fmt.Println("    Re-locking ATP file protection...")
			if err := service.StartService(cfg, service.ComponentATP); err != nil {
				log.Warn("Failed to start ATP service", "error", err)
			} else {
				fmt.Println("    ATP started")
			}
		}

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

// sameCommit returns true if the embedded commit matches the release's target_commitish.
// Safe default: if either is missing or target_commitish isn't a hex SHA, returns false
// (triggering an upgrade — better to re-download than miss an update).
func sameCommit(embedded, target string) bool {
	if embedded == "" || embedded == "none" || target == "" {
		return false
	}
	if !isHexSHA(target) {
		return false
	}
	return strings.HasPrefix(strings.ToLower(target), strings.ToLower(embedded))
}

// isHexSHA returns true if s contains only hexadecimal characters [0-9a-fA-F]
// and is at least 7 characters long (minimum short SHA length).
func isHexSHA(s string) bool {
	if len(s) < 7 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
