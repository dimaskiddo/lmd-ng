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
	fmt.Println(strings.Repeat("━", 62))
	fmt.Println()

	// --- General ---
	fmt.Printf("  %-18s %s~%s\n", "Version:", version, commit)
	configPath := cfgMgr.Viper.ConfigFileUsed()
	if configPath == "" {
		configPath = "default (built-in)"
	}
	fmt.Printf("  %-18s %s\n", "Config:", configPath)
	fmt.Printf("  %-18s %s\n", "Base Path:", cfg.App.BasePath)
	fmt.Printf("  %-18s %s\n", "Log Level:", cfg.Logging.Level)
	fmt.Println()

	// --- Database Server ---
	dbsAddress := dbsServerAddress(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	dbsClient, clientErr := dbs.NewClient(cfg)
	if clientErr == nil {
		if err := dbsClient.Ping(ctx); err == nil {
			fmt.Printf("  %-18s reachable (%s)\n", "Database Server:", dbsAddress)
			fmt.Printf("  %-18s %s\n", "ClamAV Engine:", boolYesNo(cfg.Scanner.ClamAVEnabled))
			fmt.Println()

			// Live engine stats from DBS
			statusData, statusErr := dbsClient.Status(ctx)
			if statusErr != nil {
				fmt.Printf("    %-16s unable to query (%v)\n", "Signatures:", statusErr)
			} else {
				printSignatureStats(statusData)
			}
		} else {
			fmt.Printf("  %-18s not reachable (%s)\n", "Database Server:", dbsAddress)
			fmt.Printf("                       Start database server for live engine stats.\n")
			fmt.Printf("  %-18s %s\n", "ClamAV Engine:", boolYesNo(cfg.Scanner.ClamAVEnabled))
			fmt.Println()
		}
	} else {
		fmt.Printf("  %-18s not reachable (%s): %v\n", "Database Server:", dbsAddress, clientErr)
		fmt.Printf("  %-18s %s\n", "ClamAV Engine:", boolYesNo(cfg.Scanner.ClamAVEnabled))
		fmt.Println()
	}

	// --- Version Info (from disk) ---
	printVersionInfo(cfg)
	fmt.Println()

	// --- Quarantine ---
	qMgr := quarantine.NewQuarantineManager(&cfg.Quarantine)
	quarantineCount := 0
	if entries, err := qMgr.List(ctx); err != nil {
		fmt.Printf("  %-18s unavailable (%v)\n", "Quarantine:", err)
	} else {
		quarantineCount = len(entries)
	}
	if quarantineCount == 1 {
		fmt.Printf("  %-18s 1 file\n", "Quarantine:")
	} else {
		fmt.Printf("  %-18s %d files\n", "Quarantine:", quarantineCount)
	}
	fmt.Println()

	// --- Real-Time Protector ---
	fmt.Println("  Real-Time Protector:")
	if len(cfg.Monitor.Paths) == 1 {
		fmt.Printf("    %-16s 1 path (%s)\n", "Monitoring:", cfg.Monitor.Paths[0])
	} else {
		fmt.Printf("    %-16s %d paths (%s)\n", "Monitoring:", len(cfg.Monitor.Paths), strings.Join(cfg.Monitor.Paths, ", "))
	}
	if len(cfg.Monitor.ExcludeDirs) == 1 {
		fmt.Printf("    %-16s 1 path (%s)\n", "Excluded:", cfg.Monitor.ExcludeDirs[0])
	} else {
		fmt.Printf("    %-16s %d paths (%s)\n", "Excluded:", len(cfg.Monitor.ExcludeDirs), strings.Join(cfg.Monitor.ExcludeDirs, ", "))
	}
	fmt.Println()

	// --- Scheduler ---
	fmt.Println("  Scheduler:")
	updateInterval := cfg.Scheduler.UpdateInterval
	if updateInterval == "" {
		updateInterval = "disabled"
	}
	fmt.Printf("    %-16s %s\n", "Update:", updateInterval)

	scanInterval := cfg.Scheduler.ScanInterval
	if scanInterval == "" {
		scanInterval = "disabled"
	}
	fmt.Printf("    %-16s %s\n", "Scan:", scanInterval)
	fmt.Println()

	// --- Updater ---
	u := updater.NewUpdater(cfg)
	lastUpdate := u.LastUpdateTime()
	fmt.Println("  Updater:")
	fmt.Printf("    %-16s %s\n", "Auto-Update:", boolYesNo(cfg.Updater.AutoUpdateSignatures))
	if !lastUpdate.IsZero() {
		fmt.Printf("    %-16s %s\n", "Last Update:", lastUpdate.Format("2006-01-02 15:04:05 MST"))
	} else {
		fmt.Printf("    %-16s never\n", "Last Update:")
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
	hasAny := false

	for _, name := range sigOrder {
		count := data.SignatureCounts[name]
		if count > 0 {
			fmt.Printf("    %-16s %d\n", name+":", count)
			hasAny = true
		}
	}

	// Print total from server-provided key (aggregated per engine)
	if total, ok := data.SignatureCounts["Total"]; ok && total > 0 && hasAny {
		fmt.Println("    ─────────────────────")
		fmt.Printf("    %-16s %d\n", "Total:", total)
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
	fmt.Printf("    %-16s %s\n", "LMD Version:", lmdVer)

	// ClamAV CVD versions (read from disk if enabled)
	if cfg.Scanner.ClamAVEnabled {
		clamDBPath := cfg.Scanner.ClamAVDBPath
		if clamDBPath == "" {
			clamDBPath = cfg.App.ClamAVDir
		}

		fmt.Printf("    %-16s enabled\n", "ClamAV Engine:")

		for _, dbName := range []string{"main.cvd", "daily.cvd", "bytecode.cvd"} {
			cvdPath := filepath.Join(clamDBPath, dbName)
			shortName := strings.TrimSuffix(dbName, ".cvd")
			shortName = strings.ToUpper(shortName[:1]) + shortName[1:]

			ver := readCVDVersion(cvdPath)
			if ver != "" {
				fmt.Printf("      %-9s %s\n", shortName+":", ver)
			} else {
				fmt.Printf("      %-9s not found\n", shortName+":")
			}
		}
	} else {
		fmt.Printf("    %-16s disabled\n", "ClamAV Engine:")
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

// dbsServerAddress returns the database server address string.
func dbsServerAddress(cfg *config.Config) string {
	if cfg.Server.Network == "unix" || cfg.Server.Network == "" {
		return fmt.Sprintf("unix://%s", cfg.Server.SocketPath)
	}
	return fmt.Sprintf("tcp://%s", cfg.Server.Address)
}
