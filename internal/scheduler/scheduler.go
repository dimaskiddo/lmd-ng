package scheduler

import (
	"context"
	"fmt"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
	"github.com/dimaskiddo/lmd-ng/internal/updater"
)

// Scheduler manages scheduled tasks like updates and scans.
type Scheduler struct {
	cfg         *config.Config
	cron        *cron.Cron
	coordinator *scanner.ScanCoordinator
	updater     *updater.Updater

	// Stores the entry IDs for scheduled jobs to allow easy removal/management
	updateJobID cron.EntryID
	scanJobID   cron.EntryID
}

// NewScheduler creates and initializes a new Scheduler.
func NewScheduler(cfg *config.Config, coordinator *scanner.ScanCoordinator, updater *updater.Updater) (*Scheduler, error) {
	sched := &Scheduler{
		cfg:         cfg,
		cron:        cron.New(cron.WithChain(cron.Recover(cron.DefaultLogger))),
		coordinator: coordinator,
		updater:     updater,
	}

	var err error

	// Schedule update job
	if cfg.Scheduler.UpdateInterval != "" {
		sched.updateJobID, err = sched.cron.AddFunc(cfg.Scheduler.UpdateInterval, func() {
			log.Info("Running scheduled update job")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute) // 5 minutes timeout for update
			defer cancel()

			if err := sched.updater.Update(ctx); err != nil {
				log.Error("Scheduled update job failed", "error", err)
			}
		})

		if err != nil {
			return nil, fmt.Errorf("failed to schedule update job: %w", err)
		}

		log.Info("Scheduled update job", "interval", cfg.Scheduler.UpdateInterval)
	}

	// Schedule scan job
	if cfg.Scheduler.ScanInterval != "" {
		sched.scanJobID, err = sched.cron.AddFunc(cfg.Scheduler.ScanInterval, func() {
			log.Info("Running scheduled scan job")

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour) // 2 hours timeout for daily scan
			defer cancel()

			// Iterate over configured monitor paths for scheduled scans
			for _, scanRoot := range cfg.Monitor.Paths {
				if _, err := sched.coordinator.StartScan(ctx, scanRoot); err != nil {
					log.Error("Scheduled scan job failed", "path", scanRoot, "error", err)
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

// Start starts the cron scheduler.
func (s *Scheduler) Start(ctx context.Context) {
	log.Info("LMD-NG scheduler started")
	s.cron.Start()

	// Keep the scheduler running until context is cancelled
	<-ctx.Done()
	s.Stop()
}

// Stop stops the cron scheduler.
func (s *Scheduler) Stop() {
	log.Info("Stopping LMD-NG scheduler")
	s.cron.Stop()
}
