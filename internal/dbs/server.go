package dbs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

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
		if err == io.EOF || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset by peer") {
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
		tempFile, err = os.CreateTemp("", "lmd-scan-*")
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

// sendError sends an error message back to the client.
func (s *Server) sendError(conn net.Conn, errMsg string) {
	if err := protocol.WriteFrame(conn, protocol.MsgError, []byte(errMsg)); err != nil {
		if err == io.EOF || strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset by peer") {
			log.Debug("Failed to send error to client (client disconnected)", "error", err)
		} else {
			log.Error("Failed to send error to client", "error", err)
		}
	}
}
