package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/dbs"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/updater"
)

// EngineReloader is the interface for reloading signature engines.
// Implemented by the DBS server.
type EngineReloader interface {
	ReloadEngines() error
}

// UpdateScheduler manages the periodic signature update job. It lives with the
// DBS server since it owns the signature data.
type UpdateScheduler struct {
	cfg      *config.Config
	cron     *cron.Cron
	updater  *updater.Updater
	reloader EngineReloader
	jobID    cron.EntryID
}

// NewUpdateScheduler creates and initializes the update scheduler.
func NewUpdateScheduler(cfg *config.Config, u *updater.Updater, reloader EngineReloader) (*UpdateScheduler, error) {
	sched := &UpdateScheduler{
		cfg:      cfg,
		cron:     cron.New(cron.WithChain(cron.Recover(cron.DefaultLogger))),
		updater:  u,
		reloader: reloader,
	}

	if cfg.Scheduler.UpdateInterval != "" {
		var err error
		sched.jobID, err = sched.cron.AddFunc(cfg.Scheduler.UpdateInterval, func() {
			log.Info("Running scheduled update job")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			if err := sched.updater.Update(ctx); err != nil {
				log.Error("Scheduled update job failed", "error", err)
				return
			}

			// Trigger engine reload after successful update
			if sched.reloader != nil {
				if err := sched.reloader.ReloadEngines(); err != nil {
					log.Error("Failed to reload engines after update", "error", err)
				}
			}
		})

		if err != nil {
			return nil, fmt.Errorf("failed to schedule update job: %w", err)
		}

		log.Info("Scheduled update job", "interval", cfg.Scheduler.UpdateInterval)
	}

	return sched, nil
}

// Start starts the update scheduler.
func (s *UpdateScheduler) Start(ctx context.Context) {
	log.Info("LMD-NG update scheduler started")
	s.cron.Start()

	<-ctx.Done()
	s.Stop()
}

// Stop stops the update scheduler.
func (s *UpdateScheduler) Stop() {
	log.Info("Stopping LMD-NG update scheduler")
	s.cron.Stop()
}

// ScanScheduler manages the periodic scan job. It lives with the RTP client
// since it triggers scan walks that stream files to DBS.
type ScanScheduler struct {
	cfg       *config.Config
	cron      *cron.Cron
	dbsClient *dbs.Client
	jobID     cron.EntryID
}

// NewScanScheduler creates and initializes the scan scheduler.
func NewScanScheduler(cfg *config.Config, dbsClient *dbs.Client) (*ScanScheduler, error) {
	sched := &ScanScheduler{
		cfg:       cfg,
		cron:      cron.New(cron.WithChain(cron.Recover(cron.DefaultLogger))),
		dbsClient: dbsClient,
	}

	if cfg.Scheduler.ScanInterval != "" {
		var err error
		sched.jobID, err = sched.cron.AddFunc(cfg.Scheduler.ScanInterval, func() {
			log.Info("Running scheduled scan job")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
			defer cancel()

			// Iterate over configured monitor paths for scheduled scans
			for _, scanRoot := range cfg.Monitor.Paths {
				log.Info("Scanning path via DBS", "path", scanRoot)

				// For scheduled scans, we walk the directory and scan each file
				// via the DBS client. This reuses the same streaming mechanism
				// as the RTP monitor.
				results, err := sched.dbsClient.ScanFile(ctx, scanRoot)
				if err != nil {
					log.Error("Scheduled scan job failed", "path", scanRoot, "error", err)
					continue
				}

				if len(results) > 0 {
					log.Info("Scheduled scan completed with detections", "path", scanRoot, "hits", len(results))
				}
			}
		})

		if err != nil {
			return nil, fmt.Errorf("failed to schedule scan job: %w", err)
		}

		log.Info("Scheduled scan job", "interval", cfg.Scheduler.ScanInterval)
	}

	return sched, nil
}

// Start starts the scan scheduler.
func (s *ScanScheduler) Start(ctx context.Context) {
	log.Info("LMD-NG scan scheduler started")
	s.cron.Start()

	<-ctx.Done()
	s.Stop()
}

// Stop stops the scan scheduler.
func (s *ScanScheduler) Stop() {
	log.Info("Stopping LMD-NG scan scheduler")
	s.cron.Stop()
}
