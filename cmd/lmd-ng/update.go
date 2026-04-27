package main

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/updater"
)

func updateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "LMD-NG Signature Update",
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := cfgMgr.GetConfig()

			updaterSvc := updater.NewUpdater(cfg)
			if err := updaterSvc.Update(ctx); err != nil {
				log.Error("Signatures update failed", "error", err)
				os.Exit(1)
			}

			log.Info("Signatures updated successfully.")
		},
	}
}
