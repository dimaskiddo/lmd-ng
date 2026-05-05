package rtp

import (
	"context"
	"fmt"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/dbs"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/monitor"
	"github.com/dimaskiddo/lmd-ng/internal/notifier"
	"github.com/dimaskiddo/lmd-ng/internal/quarantine"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
)

// RTP (Real-Time Protector) is the file system monitoring client that watches
// for file changes and streams modified files to the DBS server for signature
// matching. It handles quarantine locally after receiving match results.
type RTP struct {
	cfg           *config.Config
	dbsClient     *dbs.Client
	monitor       *monitor.Monitor
	notifier      notifier.Notifier
	quarantineMgr quarantine.Manager
}

// NewRTP creates a new Real-Time Protector client. It establishes a DBS client
// connection configuration and sets up the file system monitor with a scan
// callback that streams files to DBS for matching.
func NewRTP(cfg *config.Config, n notifier.Notifier) (*RTP, error) {
	dbsClient, err := dbs.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create DBS client: %w", err)
	}

	qMgr := quarantine.NewQuarantineManager(&cfg.Quarantine)

	rtp := &RTP{
		cfg:           cfg,
		dbsClient:     dbsClient,
		notifier:      n,
		quarantineMgr: qMgr,
	}

	// Create the monitor with a scan callback that uses the DBS client.
	// The callback handles:
	//   1. Streaming the file to DBS for signature matching
	//   2. Quarantining the file locally if malware is detected
	mon, err := monitor.NewMonitor(cfg, rtp.scanAndAct, n)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor: %w", err)
	}

	rtp.monitor = mon

	return rtp, nil
}

// Start begins the Real-Time Protector. It first waits for the DBS server to
// become available, then starts the file system monitor.
func (r *RTP) Start(ctx context.Context) error {
	// Wait for DBS server to be available before starting the monitor
	if err := r.dbsClient.WaitForServer(ctx); err != nil {
		return fmt.Errorf("failed waiting for DBS server: %w", err)
	}

	log.Info("LMD-NG Real-Time Protector started")

	return r.monitor.Start(ctx)
}

// Stop stops the Real-Time Protector.
func (r *RTP) Stop() error {
	log.Info("LMD-NG Real-Time Protector stopping")
	return r.monitor.Stop()
}

// scanAndAct implements the monitor.ScanFunc interface. It streams a file to
// the DBS server for scanning and handles quarantine locally if malware is
// detected. This is called by the monitor for each file system event.
func (r *RTP) scanAndAct(ctx context.Context, filePath string) ([]*scanner.ScanResult, bool) {
	results, err := r.dbsClient.ScanFile(ctx, filePath)
	if err != nil {
		log.Error("Failed to scan file via DBS", "filepath", filePath, "error", err)
		return nil, false
	}

	if len(results) == 0 {
		return nil, false
	}

	quarantined := false

	// Client-side quarantine: the DBS server only matches signatures,
	// the client handles file quarantine locally.
	if r.cfg.Quarantine.Enabled {
		log.Info("Threat detected, quarantining file", "file", filePath, "detections", len(results))

		_, qErr := r.quarantineMgr.Quarantine(ctx, filePath, results[0].SignatureName, results[0].SignatureType)
		if qErr != nil {
			log.Error("Failed to quarantine file", "file", filePath, "error", qErr)
		} else {
			quarantined = true
		}
	}

	return results, quarantined
}
