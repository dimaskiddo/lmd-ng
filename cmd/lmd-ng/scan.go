package main

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/log"
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
				log.Info("On-Demand scan completed with detections", "total_hits", len(results))
			} else {
				log.Info("On-Demand scan completed, no threats detected.")
			}
		},
	}

	return cmd
}
