package dbs

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/protocol"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
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
	ln, err := NewListener(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create listener: %w", err)
	}

	return &Server{
		cfg:      cfg,
		listener: ln,
		engines:  engines,
	}, nil
}

// Serve starts accepting client connections. It blocks until the context is
// cancelled or the listener is closed. Active connections are allowed to drain.
func (s *Server) Serve(ctx context.Context) error {
	log.Info("DBS server started, waiting for connections")

	go func() {
		<-ctx.Done()
		s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				// Expected closure during shutdown
				s.wg.Wait()
				return nil

			default:
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

// handleConnection processes a single client connection. It reads the initial
// message to determine the request type and dispatches accordingly.
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Read the first frame to determine request type
	msgType, payload, err := protocol.ReadFrame(conn)
	if err != nil {
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

	// Create a pipe: the receiver goroutine writes chunks into the pipe,
	// the scanner reads from the pipe. Neither side buffers the full file.
	pr, pw := io.Pipe()

	// Goroutine to receive chunks from the client and write them to the pipe
	receiveDone := make(chan error, 1)
	go func() {
		defer pw.Close()

		for {
			msgType, chunk, readErr := protocol.ReadFrame(conn)
			if readErr != nil {
				receiveDone <- fmt.Errorf("failed to read chunk: %w", readErr)
				return
			}

			switch msgType {
			case protocol.MsgScanChunk:
				if _, writeErr := pw.Write(chunk); writeErr != nil {
					receiveDone <- fmt.Errorf("failed to write chunk to pipe: %w", writeErr)
					return
				}

			case protocol.MsgScanEnd:
				receiveDone <- nil
				return

			default:
				receiveDone <- fmt.Errorf("unexpected message type during scan: %d", msgType)
				return
			}
		}
	}()

	// Run signature engines on the pipe reader
	engines := s.getEngines()
	var allResults []*scanner.ScanResult

	for _, engine := range engines {
		select {
		case <-ctx.Done():
			pr.Close()
			s.sendError(conn, "server shutting down")
			return

		default:
		}

		results, scanErr := engine.Scan(ctx, pr, req.FilePath)
		if scanErr != nil {
			log.Error("Engine scan failed", "engine", engine.Name(), "file", req.FilePath, "error", scanErr)
			continue
		}

		if len(results) > 0 {
			allResults = append(allResults, results...)
			// Stop on first detection — one positive is sufficient
			break
		}
	}

	// Wait for the receiver goroutine to complete
	if recvErr := <-receiveDone; recvErr != nil {
		log.Error("Chunk receiver error", "file", req.FilePath, "error", recvErr)
		// Still try to send whatever results we have
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
			log.Info("MALWARE DETECTED (via DBS)",
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

// sendError sends an error message back to the client.
func (s *Server) sendError(conn net.Conn, errMsg string) {
	if err := protocol.WriteFrame(conn, protocol.MsgError, []byte(errMsg)); err != nil {
		log.Error("Failed to send error to client", "error", err)
	}
}
