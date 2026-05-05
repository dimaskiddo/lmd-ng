package main

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/dbs"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/quarantine"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
)

func scanCmd() *cobra.Command {
	var scanPath string
	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "LMD-NG On-Demand Scan",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			scanPath = args[0]
			log.Info("Starting on-demand scan", "path", scanPath)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := cfgMgr.GetConfig()

			// Try to connect to DBS server first
			dbsClient, err := dbs.NewClient(cfg)
			if err != nil {
				log.Warn("Failed to create DBS client, falling back to local scanning", "error", err)
				runLocalScan(ctx, scanPath)
				return
			}

			// Check if DBS is reachable
			if err := dbsClient.Ping(ctx); err != nil {
				log.Warn("DBS server not reachable, falling back to local scanning", "error", err)
				runLocalScan(ctx, scanPath)
				return
			}

			log.Info("Connected to DBS server, scanning via DBS")
			runDBSScan(ctx, dbsClient, scanPath)
		},
	}

	return cmd
}

// runDBSScan performs an on-demand scan by walking the file tree locally and
// streaming each file to the DBS server for signature matching. Quarantine
// is handled client-side.
func runDBSScan(ctx context.Context, dbsClient *dbs.Client, scanPath string) {
	cfg := cfgMgr.GetConfig()

	walker, err := scanner.NewWalker(cfg)
	if err != nil {
		log.Error("Failed to create scanner walker", "error", err)
		os.Exit(1)
	}

	qMgr := quarantine.NewQuarantineManager(&cfg.Quarantine)

	var totalHits int

	walkErr := walker.Walk(ctx, scanPath, func(filePath string, fileInfo os.FileInfo) error {
		results, scanErr := dbsClient.ScanFile(ctx, filePath)
		if scanErr != nil {
			log.Error("Failed to scan file via DBS", "filepath", filePath, "error", scanErr)
			return nil // Continue scanning other files
		}

		if len(results) == 0 {
			return nil
		}

		totalHits += len(results)

		// Client-side quarantine
		if cfg.Quarantine.Enabled {
			log.Info("Threat detected, quarantining file", "file", filePath, "detections", len(results))

			_, qErr := qMgr.Quarantine(ctx, filePath, results[0].SignatureName, results[0].SignatureType)
			if qErr != nil {
				log.Error("Failed to quarantine file", "file", filePath, "error", qErr)
			}
		}

		return nil
	})

	if walkErr != nil {
		log.Error("On-Demand scan walk failed", "error", walkErr)
		os.Exit(1)
	}

	if totalHits > 0 {
		log.Info("On-Demand scan completed with detections", "total_hits", totalHits)
	} else {
		log.Info("On-Demand scan completed, no threats detected.")
	}
}

// runLocalScan performs an on-demand scan using local signature engines. This is
// the fallback path when the DBS server is not running, allowing `lmd-ng scan`
// to work standalone for ad-hoc scans.
func runLocalScan(ctx context.Context, scanPath string) {
	cfg := cfgMgr.GetConfig()

	lmdScanner, err := scanner.NewLMDSignatureScanner(cfg)
	if err != nil {
		log.Error("Failed to create LMD signature scanner", "error", err)
		os.Exit(1)
	}
	engines := []scanner.SignatureEngine{lmdScanner}

	// Add ClamAV engine if enabled
	if cfg.Scanner.ClamAVEnabled {
		clamEngine, clamErr := scanner.NewClamAVSignatureEngine(cfg)
		if clamErr != nil {
			log.Error("Failed to create ClamAV signature engine", "error", clamErr)
			os.Exit(1)
		}
		engines = append(engines, clamEngine)
	}

	walker, err := scanner.NewWalker(cfg)
	if err != nil {
		log.Error("Failed to create LMD scanner walker", "error", err)
		os.Exit(1)
	}

	coordinator := scanner.NewScanCoordinator(cfg, walker, engines)
	results, err := coordinator.StartScan(ctx, scanPath)
	if err != nil {
		log.Error("On-Demand scan failed", "error", err)
		os.Exit(1)
	}

	if len(results) > 0 {
		log.Info("On-Demand scan completed with detections (local fallback)", "total_hits", len(results))
	} else {
		log.Info("On-Demand scan completed, no threats detected.")
	}
}
