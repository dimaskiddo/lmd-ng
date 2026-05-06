package dbs

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/protocol"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
)

const (
	// dialTimeout is the maximum time to wait for a connection to DBS.
	dialTimeout = 10 * time.Second

	// pingRetryInterval is the delay between Ping retries when waiting for DBS.
	pingRetryInterval = 2 * time.Second

	// maxPingRetries is the maximum number of Ping retries before giving up.
	maxPingRetries = 30
)

// Client connects to the DBS server to stream files for signature matching.
// It opens a new TLS connection per operation (scan, ping, reload) to keep
// the protocol simple and stateless.
type Client struct {
	cfg       *config.Config
	tlsConfig *tls.Config
	network   string
	address   string
}

// NewClient creates a new DBS client from the application configuration.
func NewClient(cfg *config.Config) (*Client, error) {
	certFile, keyFile, caFile := protocol.ClientCertPaths(cfg)

	tlsConfig, err := protocol.NewClientTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create client TLS config: %w", err)
	}

	network := cfg.Server.Network
	address := cfg.Server.SocketPath

	switch network {
	case "tcp":
		address = cfg.Server.Address

	case "":
		// Default: unix on non-Windows, tcp on Windows
		if runtime.GOOS == "windows" {
			network = "tcp"
			address = cfg.Server.Address
		} else {
			network = "unix"
		}
	}

	return &Client{
		cfg:       cfg,
		tlsConfig: tlsConfig,
		network:   network,
		address:   address,
	}, nil
}

// dial establishes a TLS connection to the DBS server.
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: dialTimeout},
		Config:    c.tlsConfig,
	}

	conn, err := dialer.DialContext(ctx, c.network, c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DBS at %s://%s: %w", c.network, c.address, err)
	}

	return conn, nil
}

// Ping sends a health-check request to the DBS server.
func (c *Client) Ping(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := protocol.WriteFrame(conn, protocol.MsgPing, nil); err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}

	msgType, _, err := protocol.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("failed to read pong: %w", err)
	}

	if msgType != protocol.MsgPong {
		return fmt.Errorf("expected pong (0x%02x), got 0x%02x", protocol.MsgPong, msgType)
	}

	return nil
}

// WaitForServer blocks until the DBS server is reachable or the context is
// cancelled. It retries Ping with exponential backoff.
func (c *Client) WaitForServer(ctx context.Context) error {
	log.Info("Waiting for DBS server to become available", "address", c.address)

	for i := 0; i < maxPingRetries; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()

		default:
		}

		if err := c.Ping(ctx); err == nil {
			log.Info("DBS server is available")
			return nil
		}

		log.Debug("Retrying to connect DBS server", "attempt", i+1, "max", maxPingRetries)

		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-time.After(pingRetryInterval):
		}
	}

	return fmt.Errorf("DBS server not available after %d retries at %s://%s", maxPingRetries, c.network, c.address)
}

// ScanFile streams a file to the DBS server for signature matching and returns
// the scan results. The file is read in chunks and streamed over the TLS
// connection — neither client nor server buffers the full file in memory.
func (c *Client) ScanFile(ctx context.Context, filePath string) ([]*scanner.ScanResult, error) {
	// Stat the file first
	info, err := os.Lstat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("File no longer exists, skipping scan", "filepath", filePath)
			return nil, nil
		}

		if os.IsPermission(err) {
			log.Warn("Permission denied to stat file", "filepath", filePath, "error", err)
			return nil, nil
		}

		return nil, fmt.Errorf("failed to stat file %s: %w", filePath, err)
	}

	if !info.Mode().IsRegular() {
		return nil, nil
	}

	// Open the file
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsPermission(err) {
			log.Warn("Permission denied to open file", "filepath", filePath, "error", err)
			return nil, nil
		}

		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	// Connect to DBS
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Send scan request header
	reqPayload := protocol.EncodeScanRequest(&protocol.ScanRequestHeader{
		FilePath: filePath,
		FileSize: info.Size(),
	})

	if err := protocol.WriteFrame(conn, protocol.MsgScanRequest, reqPayload); err != nil {
		return nil, fmt.Errorf("failed to send scan request for %s: %w", filePath, err)
	}

	// Stream file data in chunks
	buf := make([]byte, protocol.MaxChunkSize)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		default:
		}

		n, readErr := file.Read(buf)
		if n > 0 {
			if writeErr := protocol.WriteFrame(conn, protocol.MsgScanChunk, buf[:n]); writeErr != nil {
				return nil, fmt.Errorf("failed to send chunk for %s: %w", filePath, writeErr)
			}
		}

		if readErr == io.EOF {
			break
		}

		if readErr != nil {
			return nil, fmt.Errorf("failed to read file %s: %w", filePath, readErr)
		}
	}

	// Signal end of file data
	if err := protocol.WriteFrame(conn, protocol.MsgScanEnd, nil); err != nil {
		return nil, fmt.Errorf("failed to send scan end for %s: %w", filePath, err)
	}

	// Read the scan result
	msgType, resultPayload, err := protocol.ReadFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read scan result for %s: %w", filePath, err)
	}

	if msgType == protocol.MsgError {
		return nil, fmt.Errorf("DBS server error scanning %s: %s", filePath, string(resultPayload))
	}

	if msgType != protocol.MsgScanResult {
		return nil, fmt.Errorf("unexpected message type 0x%02x from DBS for %s", msgType, filePath)
	}

	resultMsg, err := protocol.DecodeScanResult(resultPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode scan result for %s: %w", filePath, err)
	}

	if !resultMsg.Matched {
		return nil, nil
	}

	// Convert protocol results to scanner results
	results := make([]*scanner.ScanResult, len(resultMsg.Results))
	for i, entry := range resultMsg.Results {
		results[i] = &scanner.ScanResult{
			SignatureName: entry.SignatureName,
			SignatureType: entry.SignatureType,
			FilePath:      filePath,
			DetectionID:   entry.DetectionID,
		}
	}

	return results, nil
}

// SendReload sends a MsgReloadSignatures command to the DBS server and waits
// for acknowledgment. Used by `lmd-ng update` after writing new signatures.
func (c *Client) SendReload(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := protocol.WriteFrame(conn, protocol.MsgReloadSignatures, nil); err != nil {
		return fmt.Errorf("failed to send reload command: %w", err)
	}

	msgType, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("failed to read reload response: %w", err)
	}

	if msgType == protocol.MsgError {
		return fmt.Errorf("DBS reload failed: %s", string(payload))
	}

	if msgType != protocol.MsgReloadAck {
		return fmt.Errorf("unexpected response to reload: 0x%02x", msgType)
	}

	log.Info("DBS signature reload completed successfully")
	return nil
}
