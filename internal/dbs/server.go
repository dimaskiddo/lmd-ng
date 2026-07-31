package dbs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/protocol"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
	"github.com/dimaskiddo/lmd-ng/internal/util"
)

// Server is the centralized Database Signature Service. It loads signature
// engines into memory once and handles scan requests from clients (RTP, scan CLI)
// by receiving streamed file data and performing pattern matching.
type Server struct {
	cfg      *config.Config
	listener net.Listener
	engines  []scanner.SignatureEngine
	mu       sync.RWMutex
	wg       sync.WaitGroup

	// EngineFactory rebuilds engines from signature databases on disk.
	// Set by the caller (daemon command) at wiring time.
	EngineFactory func(cfg *config.Config) ([]scanner.SignatureEngine, error)
}

// NewServer creates a new DBS server. It builds signature engines from the
// current configuration and prepares the network listener.
func NewServer(cfg *config.Config, engines []scanner.SignatureEngine) (*Server, error) {
	ln, err := newListener(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	s := &Server{
		cfg:      cfg,
		listener: ln,
		engines:  engines,
	}

	// Clean up temp files from prior unclean shutdowns
	s.cleanOrphanTempFiles()

	return s, nil
}

// Serve starts accepting client connections. It blocks until the context is
// cancelled or the listener is closed. Active connections are allowed to drain.
func (s *Server) Serve(ctx context.Context) error {
	log.Info("DBS server started, waiting for connections")

	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	// Periodic cleanup of stale temp files
	go s.startTempCleanup(ctx)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				// Expected closure during shutdown
				s.wg.Wait()
				return nil

			default:
				if err == net.ErrClosed {
					// Listener closed (e.g. by Shutdown or ctx cancellation goroutine)
					s.wg.Wait()
					return nil
				}
				log.Error("Failed to accept connection", "error", err)
				continue
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(ctx, conn)
		}()
	}
}

// Shutdown closes the listener and waits for all active connections to finish.
func (s *Server) Shutdown() {
	log.Info("DBS server shutting down")

	s.listener.Close()
	s.wg.Wait()

	// Clean up Unix socket file
	if s.cfg.Server.Network == "unix" || s.cfg.Server.Network == "" {
		os.Remove(s.cfg.Server.SocketPath)
	}

	log.Info("DBS server shut down successfully")
}

// ReloadEngines rebuilds all signature engines from their database files.
// Active scans continue using the old engines; new scans pick up fresh ones.
func (s *Server) ReloadEngines() error {
	if s.EngineFactory == nil {
		return fmt.Errorf("engine factory not set, cannot reload engines")
	}

	log.Info("Reloading signature engines")

	newEngines, err := s.EngineFactory(s.cfg)
	if err != nil {
		return fmt.Errorf("failed to create new engines during reload: %w", err)
	}

	s.mu.Lock()
	s.engines = newEngines
	s.mu.Unlock()

	// Hint Go GC to collect old engine data promptly
	runtime.GC()

	engineNames := make([]string, len(newEngines))
	for i, e := range newEngines {
		engineNames[i] = e.Name()
	}

	log.Info("Signature engines reloaded successfully", "engines", engineNames)
	return nil
}

// getEngines returns a snapshot of the current engine list.
func (s *Server) getEngines() []scanner.SignatureEngine {
	s.mu.RLock()
	defer s.mu.RUnlock()

	engines := make([]scanner.SignatureEngine, len(s.engines))
	copy(engines, s.engines)

	return engines
}

// cleanOrphanTempFiles removes any leftover lmd-scan-* temp files from prior
// crashes or unclean shutdowns. Called once at server startup before accepting
// connections — no active scan references exist at this point.
func (s *Server) cleanOrphanTempFiles() {
	tmpDir := filepath.Join(s.cfg.App.BasePath, "tmp")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn("Failed to read temp directory for cleanup", "path", tmpDir, "error", err)
		}
		return
	}

	var cleaned int
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), "lmd-scan-") {
			path := filepath.Join(tmpDir, entry.Name())
			if removeErr := os.Remove(path); removeErr != nil {
				log.Debug("Failed to remove orphaned temp file", "path", path, "error", removeErr)
			} else {
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		log.Info("Cleaned up orphaned temp files", "count", cleaned, "directory", tmpDir)
	}
}

// startTempCleanup periodically removes stale lmd-scan-* temp files.
// Runs until ctx is cancelled. Catches files leaked by panics or edge cases
// where the deferred cleanup in handleScanRequest did not execute.
func (s *Server) startTempCleanup(ctx context.Context) {
	const cleanupInterval = 1 * time.Minute
	const staleThreshold = 5 * time.Minute

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.removeStaleTempFiles(staleThreshold)
		}
	}
}

// removeStaleTempFiles deletes lmd-scan-* files older than the given threshold.
func (s *Server) removeStaleTempFiles(threshold time.Duration) {
	tmpDir := filepath.Join(s.cfg.App.BasePath, "tmp")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return
	}

	now := time.Now()
	var cleaned int
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "lmd-scan-") {
			continue
		}

		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}

		if now.Sub(info.ModTime()) > threshold {
			path := filepath.Join(tmpDir, entry.Name())
			if removeErr := os.Remove(path); removeErr != nil {
				log.Debug("Failed to remove stale temp file", "path", path, "error", removeErr)
			} else {
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		log.Info("Cleaned up stale temp files", "count", cleaned, "directory", tmpDir)
	}
}

// handleConnection processes a single client connection. It reads the initial
// message to determine the request type and dispatches accordingly.
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Set read deadline to prevent goroutine leak from stalled clients
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read the first frame to determine request type
	msgType, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
			strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset by peer") {
			log.Debug("Client disconnected before sending request", "error", err)
			return
		}

		log.Error("Failed to read initial frame from client", "error", err)
		s.sendError(conn, fmt.Sprintf("failed to read frame: %v", err))
		return
	}

	switch msgType {
	case protocol.MsgScanRequest:
		s.handleScanRequest(ctx, conn, payload)

	case protocol.MsgPing:
		if err := protocol.WriteFrame(conn, protocol.MsgPong, nil); err != nil {
			log.Error("Failed to send pong", "error", err)
		}

	case protocol.MsgReloadSignatures:
		s.handleReloadRequest(conn)

	case protocol.MsgStatusRequest:
		s.handleStatusRequest(conn)

	default:
		log.Warn("Unknown message type received", "type", msgType)
		s.sendError(conn, fmt.Sprintf("unknown message type: %d", msgType))
	}
}

// handleScanRequest processes a file scan request. It receives chunked file
// data from the client via an io.Pipe, feeds it to the signature engines,
// and sends the results back.
func (s *Server) handleScanRequest(ctx context.Context, conn net.Conn, requestPayload []byte) {
	req, err := protocol.DecodeScanRequest(requestPayload)
	if err != nil {
		log.Error("Failed to decode scan request", "error", err)
		s.sendError(conn, fmt.Sprintf("invalid scan request: %v", err))
		return
	}

	log.Debug("Scan request received", "file", req.FilePath, "size", req.FileSize)

	// Buffer Once Mechanism:
	// We read the entire incoming stream into a seekable buffer before passing it
	// to the signature engines. This allows multiple engines to scan the same
	// data stream without the first engine consuming the pipe.
	var memoryBuffer *bytes.Buffer
	var tempFile *os.File
	var useTempFile bool

	bufferLimit, err := util.ParseSizeString(s.cfg.Server.StreamBufferLimit)
	if err != nil || bufferLimit <= 0 {
		bufferLimit = 10 * 1024 * 1024 // Default to 10MB if invalid or empty
	}

	if req.FileSize > bufferLimit {
		useTempFile = true

		tmpDir := filepath.Join(s.cfg.App.BasePath, "tmp")
		if mkdirErr := os.MkdirAll(tmpDir, 0o700); mkdirErr != nil {
			log.Error("Failed to create temp directory", "path", tmpDir, "error", mkdirErr)
			s.sendError(conn, "internal server error: temp directory creation failed")
			return
		}

		tempFile, err = os.CreateTemp(tmpDir, "lmd-scan-*")
		if err != nil {
			log.Error("Failed to create temp file for scan", "error", err)
			s.sendError(conn, "internal server error: temp file creation failed")
			return
		}
		defer func() {
			tempFile.Close()
			os.Remove(tempFile.Name())
		}()
	} else {
		memoryBuffer = &bytes.Buffer{}
		if req.FileSize > 0 {
			memoryBuffer.Grow(int(req.FileSize))
		}
	}

	for {
		// Check for shutdown before blocking on network read
		select {
		case <-ctx.Done():
			log.Debug("Scan interrupted by shutdown", "file", req.FilePath)
			s.sendError(conn, "server shutting down")
			return
		default:
		}

		// Set per-read deadline to prevent goroutine leak from stalled clients
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		msgType, chunk, readErr := protocol.ReadFrame(conn)
		if readErr != nil {
			log.Error("Failed to read chunk", "error", readErr)
			s.sendError(conn, "failed to read stream")
			return
		}

		switch msgType {
		case protocol.MsgScanChunk:
			if useTempFile {
				if _, writeErr := tempFile.Write(chunk); writeErr != nil {
					log.Error("Failed to write to temp file", "error", writeErr)
					s.sendError(conn, "internal server error: write failed")
					return
				}
			} else {
				memoryBuffer.Write(chunk)
			}

		case protocol.MsgScanEnd:
			// Stream received completely, break out of loop
			goto ScanPhase

		default:
			log.Error("Unexpected message type during scan", "type", msgType)
			s.sendError(conn, "unexpected message type")
			return
		}
	}

ScanPhase:
	var seekableReader io.ReadSeeker
	if useTempFile {
		if _, err := tempFile.Seek(0, io.SeekStart); err != nil {
			log.Error("Failed to seek temp file", "error", err)
			s.sendError(conn, "internal server error: seek failed")
			return
		}
		seekableReader = tempFile
	} else {
		seekableReader = bytes.NewReader(memoryBuffer.Bytes())
	}

	// Run signature engines on the seekable reader via shared scan function
	engines := s.getEngines()
	allResults, scanErr := scanner.ScanDataWithEngines(ctx, engines, seekableReader, req.FilePath)
	if scanErr != nil {
		log.Error("Scan failed", "file", req.FilePath, "error", scanErr)
		s.sendError(conn, fmt.Sprintf("scan failed: %v", scanErr))
		return
	}

	// Build and send the result message
	resultMsg := &protocol.ScanResultMessage{
		Matched: len(allResults) > 0,
		Results: make([]protocol.ScanResultEntry, len(allResults)),
	}

	for i, r := range allResults {
		resultMsg.Results[i] = protocol.ScanResultEntry{
			SignatureName: r.SignatureName,
			SignatureType: r.SignatureType,
			DetectionID:   r.DetectionID,
		}
	}

	resultPayload := protocol.EncodeScanResult(resultMsg)
	if err := protocol.WriteFrame(conn, protocol.MsgScanResult, resultPayload); err != nil {
		log.Error("Failed to send scan result", "file", req.FilePath, "error", err)
	}

	if len(allResults) > 0 {
		for _, r := range allResults {
			log.Info("MALWARE DETECTED (DBS)",
				"file", r.FilePath,
				"signature", r.SignatureName,
				"type", r.SignatureType,
				"detection_id", r.DetectionID)
		}
	}
}

// handleReloadRequest processes a signature reload request from a client
// (typically sent by `lmd-ng update` after writing new signatures to disk).
func (s *Server) handleReloadRequest(conn net.Conn) {
	log.Info("Signature reload request received from client")

	if err := s.ReloadEngines(); err != nil {
		log.Error("Failed to reload engines", "error", err)
		s.sendError(conn, fmt.Sprintf("reload failed: %v", err))
		return
	}

	if err := protocol.WriteFrame(conn, protocol.MsgReloadAck, nil); err != nil {
		log.Error("Failed to send reload acknowledgment", "error", err)
	}
}

// handleStatusRequest aggregates engine statistics and returns them to the client.
func (s *Server) handleStatusRequest(conn net.Conn) {
	engines := s.getEngines()

	data := &protocol.StatusData{
		SignatureCounts: make(map[string]int),
	}

	var totalSigs int
	for _, engine := range engines {
		data.EngineNames = append(data.EngineNames, engine.Name())

		switch e := engine.(type) {
		case *scanner.LMDSignatureScanner:
			data.SignatureCounts["MD5 Hashes"] += e.MD5Count()
			data.SignatureCounts["SHA256 Hashes"] += e.SHA256Count()
			data.SignatureCounts["HEX Patterns"] += e.HEXCount()
			data.SignatureCounts["RFXN Signatures"] += e.RFXNCount()
			totalSigs += e.MD5Count() + e.SHA256Count() + e.HEXCount() + e.RFXNCount()

		case *scanner.ClamAVSignatureEngine:
			data.SignatureCounts["HDB Signatures"] += e.HDBCount()
			data.SignatureCounts["NDB Signatures"] += e.NDBCount()
			data.SignatureCounts["MDB Signatures"] += e.MDBCount()
			totalSigs += e.TotalSignatures()

			if cvdVersions := e.CVDVersions(); len(cvdVersions) > 0 {
				data.CVDDatabaseVersions = cvdVersions
			}
		}
	}
	data.SignatureCounts["Total"] = totalSigs

	payload, err := protocol.EncodeStatusData(data)
	if err != nil {
		log.Error("Failed to encode status data", "error", err)
		s.sendError(conn, "internal server error: failed to encode status")
		return
	}

	if err := protocol.WriteFrame(conn, protocol.MsgStatusResponse, payload); err != nil {
		log.Error("Failed to send status response", "error", err)
	}
}

// sendError sends an error message back to the client.
func (s *Server) sendError(conn net.Conn, errMsg string) {
	if err := protocol.WriteFrame(conn, protocol.MsgError, []byte(errMsg)); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
			strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset by peer") {
			log.Debug("Failed to send error to client (client disconnected)", "error", err)
		} else {
			log.Error("Failed to send error to client", "error", err)
		}
	}
}
