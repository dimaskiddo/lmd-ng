package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/dbs"
	"github.com/dimaskiddo/lmd-ng/internal/protocol"
	"github.com/dimaskiddo/lmd-ng/internal/quarantine"
	"github.com/dimaskiddo/lmd-ng/internal/updater"
)

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Display LMD-NG status and statistics",
		Run:   runStatus,
	}
}

func runStatus(cmd *cobra.Command, args []string) {
	cfg := cfgMgr.GetConfig()

	fmt.Println("LMD-NG Status")
	fmt.Println("By Dimas Restu H <drh.dimasrestu@gmail.com>")
	fmt.Println(strings.Repeat("━", 62))
	fmt.Println()

	// --- General ---
	fmt.Printf("  Version:       %s~%s\n", version, commit)
	fmt.Printf("  Config:        %s\n", cfgFile)
	fmt.Printf("  Base Path:     %s\n", cfg.App.BasePath)
	fmt.Printf("  Log Level:     %s\n", cfg.Logging.Level)
	fmt.Println()

	// --- DBS Server ---
	dbsAddress := dbsServerAddress(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	dbsClient, clientErr := dbs.NewClient(cfg)
	if clientErr == nil {
		if err := dbsClient.Ping(ctx); err == nil {
			fmt.Printf("  DBS Server:    reachable (%s)\n", dbsAddress)
			fmt.Printf("  ClamAV Engine: %s\n", boolYesNo(cfg.Scanner.ClamAVEnabled))
			fmt.Println()

			// Live engine stats from DBS
			statusData, statusErr := dbsClient.Status(ctx)
			if statusErr != nil {
				fmt.Printf("  Signatures:    unable to query (%v)\n", statusErr)
			} else {
				printSignatureStats(statusData)
			}
		} else {
			fmt.Printf("  DBS Server:    not reachable (%s)\n", dbsAddress)
			fmt.Printf("                 Start DBS server for live engine stats.\n")
			fmt.Printf("  ClamAV Engine: %s\n", boolYesNo(cfg.Scanner.ClamAVEnabled))
			fmt.Println()
		}
	} else {
		fmt.Printf("  DBS Server:    not reachable (%s): %v\n", dbsAddress, clientErr)
		fmt.Printf("  ClamAV Engine: %s\n", boolYesNo(cfg.Scanner.ClamAVEnabled))
		fmt.Println()
	}

	// --- Version Info (from disk) ---
	printVersionInfo(cfg)
	fmt.Println()

	// --- Quarantine ---
	qMgr := quarantine.NewQuarantineManager(&cfg.Quarantine)
	quarantineCount := 0
	if entries, err := qMgr.List(ctx); err != nil {
		fmt.Printf("  Quarantine:     unavailable (%v)\n", err)
	} else {
		quarantineCount = len(entries)
	}
	if quarantineCount == 1 {
		fmt.Printf("  Quarantine:     1 file\n")
	} else {
		fmt.Printf("  Quarantine:     %d files\n", quarantineCount)
	}
	fmt.Println()

	// --- RTP ---
	fmt.Println("  RTP:")
	if len(cfg.Monitor.Paths) == 1 {
		fmt.Printf("    Monitoring:   1 path (%s)\n", cfg.Monitor.Paths[0])
	} else {
		fmt.Printf("    Monitoring:   %d paths (%s)\n", len(cfg.Monitor.Paths), strings.Join(cfg.Monitor.Paths, ", "))
	}
	if len(cfg.Monitor.ExcludeDirs) == 1 {
		fmt.Printf("    Excluded:     1 path (%s)\n", cfg.Monitor.ExcludeDirs[0])
	} else {
		fmt.Printf("    Excluded:     %d paths (%s)\n", len(cfg.Monitor.ExcludeDirs), strings.Join(cfg.Monitor.ExcludeDirs, ", "))
	}
	fmt.Println()

	// --- Scheduler ---
	fmt.Println("  Scheduler:")
	fmt.Printf("    Update:       %s\n", cfg.Scheduler.UpdateInterval)
	fmt.Printf("    Scan:         %s\n", cfg.Scheduler.ScanInterval)
	fmt.Println()

	// --- Updater ---
	u := updater.NewUpdater(cfg)
	lastUpdate := u.LastUpdateTime()
	fmt.Println("  Updater:")
	fmt.Printf("    Auto-Update:  %s\n", boolYesNo(cfg.Updater.AutoUpdateSignatures))
	if !lastUpdate.IsZero() {
		fmt.Printf("    Last Update:  %s UTC\n", lastUpdate.UTC().Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("    Last Update:  never\n")
	}
}

// printSignatureStats prints engine signature counts from DBS status data.
func printSignatureStats(data *protocol.StatusData) {
	if data == nil {
		return
	}

	// Ordered display of signature types — only show non-zero counts.
	sigOrder := []string{
		"MD5 Hashes",
		"SHA256 Hashes",
		"HEX Patterns",
		"RFXN Signatures",
		"HDB Signatures",
		"NDB Signatures",
		"MDB Signatures",
	}

	fmt.Println("  Signatures:")
	total := 0

	for _, name := range sigOrder {
		count := data.SignatureCounts[name]
		if count > 0 {
			fmt.Printf("    %-15s %d\n", name+":", count)
			total += count
		}
	}

	// Print total when multiple engine types contributed
	if total > 0 && len(data.EngineNames) > 1 {
		fmt.Println("    ─────────────────────")
		fmt.Printf("    Total:        %d\n", total)
	}
}

// printVersionInfo prints signature version information from disk.
func printVersionInfo(cfg *config.Config) {
	fmt.Println("  Version Info:")

	// LMD version
	u := updater.NewUpdater(cfg)
	lmdVer, err := u.CurrentLMDVersion()
	if err != nil {
		lmdVer = "not found"
	}
	fmt.Printf("    LMD Version:  %s\n", lmdVer)

	// ClamAV CVD versions (read from disk if enabled)
	if cfg.Scanner.ClamAVEnabled {
		clamDBPath := cfg.Scanner.ClamAVDBPath
		if clamDBPath == "" {
			clamDBPath = cfg.App.ClamAVDir
		}

		fmt.Println("    ClamAV Engine: enabled")

		for _, dbName := range []string{"main.cvd", "daily.cvd", "bytecode.cvd"} {
			cvdPath := filepath.Join(clamDBPath, dbName)
			shortName := strings.TrimSuffix(dbName, ".cvd")
			shortName = strings.ToUpper(shortName[:1]) + shortName[1:]

			ver := readCVDVersion(cvdPath)
			if ver != "" {
				fmt.Printf("      %-12s %s\n", shortName+":", ver)
			} else {
				fmt.Printf("      %-12s not found\n", shortName+":")
			}
		}
	} else {
		fmt.Println("    ClamAV Engine: disabled")
	}
}

// readCVDVersion reads the version number from the first 512 bytes of a CVD file.
func readCVDVersion(cvdPath string) string {
	f, err := os.Open(cvdPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	header := make([]byte, 512)
	n, err := f.Read(header)
	if err != nil || n < 10 {
		return ""
	}

	// Parse CVD header: ClamAV-VDB:buildtime:version:sigs:flevel:...
	headerStr := strings.TrimRight(string(header), "\x00 \n\r\t")
	parts := strings.Split(headerStr, ":")
	if len(parts) < 4 {
		return ""
	}

	return parts[2]
}

// boolYesNo returns "enabled" or "disabled" based on the boolean value.
func boolYesNo(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}

// dbsServerAddress returns the DBS server address string.
func dbsServerAddress(cfg *config.Config) string {
	if cfg.Server.Network == "unix" || cfg.Server.Network == "" {
		return fmt.Sprintf("unix://%s", cfg.Server.SocketPath)
	}
	return fmt.Sprintf("tcp://%s", cfg.Server.Address)
}
