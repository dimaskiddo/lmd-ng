package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/quarantine"
)

const manualQuarantineInfo = "Manually Quarantined"

func quarantineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quarantine",
		Short: "LMD-NG Quarantine Management",
	}

	cmd.AddCommand(quarantineListCmd())
	cmd.AddCommand(quarantineAddCmd())
	cmd.AddCommand(quarantineRestoreCmd())
	cmd.AddCommand(quarantineRemoveCmd())

	return cmd
}

// quarantineListCmd returns the `quarantine list` subcommand.
// It prints all quarantined files as a formatted table showing the short ID,
// original file path, detection info, and whether the file is encrypted.
func quarantineListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all quarantined files",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := cfgMgr.GetConfig()
			qm := quarantine.NewQuarantineManager(&cfg.Quarantine)

			entries, err := qm.List(ctx)
			if err != nil {
				log.Error("Failed to list quarantined files", "error", err)
				os.Exit(1)
			}

			if len(entries) == 0 {
				fmt.Println("No quarantined files found.")
				return
			}

			// Use tabwriter to produce aligned columnar output without external deps.
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			defer w.Flush()

			fmt.Fprintln(w, "SHORT ID\tORIGINAL PATH\tDETECTION\tENGINE\tMODE\tOWNER\tQUARANTINED AT\tENCRYPTED")
			fmt.Fprintln(w, "--------\t-------------\t---------\t------\t----\t-----\t--------------\t---------")

			for _, e := range entries {
				encrypted := "no"
				if e.Encrypted {
					encrypted = "yes"
				}

				owner := fmt.Sprintf("%s:%s", e.Username, e.GroupName)

				quarantinedAt := "-"
				if !e.QuarantinedAt.IsZero() {
					quarantinedAt = e.QuarantinedAt.Format("2006-01-02 15:04:05")
				}

				mode := e.FileMode
				if mode == "" {
					mode = "-"
				}

				engine := e.DetectionEngine
				if engine == "" {
					engine = "manual"
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					e.ShortID, e.OriginalPath, e.DetectionInfo, engine, mode, owner, quarantinedAt, encrypted)
			}
		},
	}
}

// quarantineAddCmd returns the `quarantine add <file>` subcommand.
// It manually moves a file into quarantine using the fixed detection label
// "Manually Quarantined" for consistency with scan-triggered quarantine records.
func quarantineAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <file>",
		Short: "Manually quarantine a file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filePath := args[0]

			// Verify the target file exists and is a regular file before proceeding.
			info, err := os.Stat(filePath)
			if err != nil {
				if os.IsNotExist(err) {
					log.Error("File not found", "path", filePath)
				} else {
					log.Error("Failed to stat file", "path", filePath, "error", err)
				}
				os.Exit(1)
			}

			if info.IsDir() {
				log.Error("Target is a directory; only files can be quarantined", "path", filePath)
				os.Exit(1)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := cfgMgr.GetConfig()
			qm := quarantine.NewQuarantineManager(&cfg.Quarantine)

			absFilePath, err := filepath.Abs(filePath)
			if err != nil {
				absFilePath = filePath
			}

			quarantinePath, err := qm.Quarantine(ctx, filePath, manualQuarantineInfo, "")
			if err != nil {
				log.Error("Failed to quarantine file", "path", filePath, "error", err)
				os.Exit(1)
			}

			log.Info("File quarantined successfully", "original_path", absFilePath, "quarantine_path", quarantinePath)
		},
	}
}

// quarantineRestoreCmd returns the `quarantine restore <id|path>` subcommand.
// The argument may be:
//   - A full absolute path to the .quarantined file.
//   - A full 32-char hex quarantine ID.
//   - A short ID prefix (≥ 4 chars) shown in `quarantine list`.
func quarantineRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <id|path>",
		Short: "Restore a quarantined file to its original location",
		Long: `Restore a quarantined file back to its original path.

The argument can be:
  - A short ID (shown in 'quarantine list', minimum 4 chars)
  - A full 32-character quarantine ID
  - An absolute path to the quarantined file`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ref := args[0]

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := cfgMgr.GetConfig()
			qm := quarantine.NewQuarantineManager(&cfg.Quarantine)

			// Resolve the reference to an absolute quarantine path.
			quarantinePath, err := qm.ResolveByID(ref)
			if err != nil {
				log.Error("Failed to resolve quarantine entry", "ref", ref, "error", err)
				os.Exit(1)
			}

			originalPath, err := qm.Restore(ctx, quarantinePath)
			if err != nil {
				log.Error("Failed to restore quarantined file", "quarantine_path", quarantinePath, "error", err)
				os.Exit(1)
			}

			log.Info("File restored successfully", "restored_to", originalPath)
		},
	}
}

// quarantineRemoveCmd returns the `quarantine remove <id|path>` subcommand.
// It permanently deletes a quarantined file and its metadata sidecar.
// A --force flag is required to proceed, acting as a safety confirmation gate
// since this operation is irreversible and the original file cannot be recovered.
func quarantineRemoveCmd() *cobra.Command {
	var force bool

	cmd := &cobra.Command{
		Use:   "remove <id|path>",
		Short: "Permanently delete a quarantined file",
		Long: `Permanently delete a quarantined file and its metadata record.

WARNING: This operation is irreversible. The original file cannot be recovered.

The argument can be:
  - A short ID (shown in 'quarantine list', minimum 4 chars)
  - A full 32-character quarantine ID
  - An absolute path to the quarantined file

You must pass --force to confirm the deletion.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if !force {
				fmt.Fprintln(os.Stderr, "ERROR: quarantine remove is irreversible. Pass --force to confirm permanent deletion.")
				os.Exit(1)
			}

			ref := args[0]

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			cfg := cfgMgr.GetConfig()
			qm := quarantine.NewQuarantineManager(&cfg.Quarantine)

			// Resolve the reference to an absolute quarantine path.
			quarantinePath, err := qm.ResolveByID(ref)
			if err != nil {
				log.Error("Failed to resolve quarantine entry", "ref", ref, "error", err)
				os.Exit(1)
			}

			if err := qm.Remove(ctx, quarantinePath); err != nil {
				log.Error("Failed to remove quarantined file", "quarantine_path", quarantinePath, "error", err)
				os.Exit(1)
			}

			log.Info("Quarantined file permanently deleted", "quarantine_path", quarantinePath)
		},
	}

	cmd.Flags().BoolVarP(&force, "force", "f", false, "Confirm permanent deletion (required)")

	return cmd
}
