package dbs

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/protocol"
	"github.com/dimaskiddo/lmd-ng/internal/scanner"
	"github.com/dimaskiddo/lmd-ng/internal/util"
)

const (
	// dialTimeout is the maximum time to wait for a connection to DBS.
	dialTimeout = 10 * time.Second

	// pingRetryInterval is the delay between Ping retries when waiting for DBS.
	pingRetryInterval = 2 * time.Second

	// maxPingRetries is the maximum number of Ping retries before giving up.
	maxPingRetries = 30

	// connectionIdleTimeout is the maximum time a pooled connection can sit
	// idle before being discarded on retrieval. Must be shorter than any
	// server-side or OS-level idle connection timeout.
	connectionIdleTimeout = 4 * time.Minute
)

// pooledConn wraps a net.Conn with idle-time tracking for health-checked
// connection pool reuse.
type pooledConn struct {
	conn     net.Conn
	idleTime time.Time
}

// scanBufPool reuses byte buffers for streaming file chunks to DBS,
// reducing GC pressure during concurrent scans.
var scanBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, protocol.MaxChunkSize)
		return &buf
	},
}

// isConnFatal reports whether err means the underlying connection is dead.
func isConnFatal(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset by peer")
}

// Client connects to the DBS server to stream files for signature matching.
type Client struct {
	tlsConfig       *tls.Config
	network         string
	address         string
	pool            chan *pooledConn
	sem             chan struct{}
	maxSymlinkDepth int
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
		tlsConfig:       tlsConfig,
		network:         network,
		address:         address,
		pool:            make(chan *pooledConn, cfg.Server.ConnectionPoolLimit),
		sem:             make(chan struct{}, cfg.Scanner.ConcurrencyLimit),
		maxSymlinkDepth: cfg.Scanner.MaxSymlinkDepth,
	}, nil
}

// getConn retrieves a healthy connection from the pool or dials a new one.
func (c *Client) getConn(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case pconn := <-c.pool:
			if time.Since(pconn.idleTime) > connectionIdleTimeout {
				pconn.conn.Close()
				continue
			}
			if err := c.connHealthCheck(pconn.conn); err != nil {
				log.Debug("Pooled connection is dead, discarding", "error", err)
				pconn.conn.Close()
				continue
			}
			return pconn.conn, nil
		default:
			return c.dial(ctx)
		}
	}
}

// releaseConn returns connection to the pool, or closes it if the pool is full.
func (c *Client) releaseConn(conn net.Conn) {
	pconn := &pooledConn{
		conn:     conn,
		idleTime: time.Now(),
	}
	select {
	case c.pool <- pconn:
	default:
		conn.Close()
	}
}

// connHealthCheck verifies a connection is still alive using an expired read deadline.
func (c *Client) connHealthCheck(conn net.Conn) error {
	conn.SetReadDeadline(time.Now().Add(-time.Second))
	var buf [1]byte
	_, err := conn.Read(buf[:])
	conn.SetReadDeadline(time.Time{})

	if err == nil {
		conn.Close()
		return fmt.Errorf("unexpected data on idle pooled connection")
	}

	// Timeout means connection is alive, just no data buffered
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return nil
	}

	// Any other error: EOF, broken pipe, reset — connection is dead
	return err
}

// drainPool closes and discards all idle connections in the pool.
// Called when a connection error suggests pooled connections may be stale.
func (c *Client) drainPool() {
	for {
		select {
		case pconn := <-c.pool:
			pconn.conn.Close()
		default:
			return
		}
	}
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
		return fmt.Errorf("failed to dial DBS for ping: %w", err)
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
// the scan results. Connection errors are retried once; file errors are not.
func (c *Client) ScanFile(ctx context.Context, filePath string) ([]*scanner.ScanResult, error) {
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

	if info.Mode()&os.ModeSymlink != 0 {
		resolved, err := util.ResolveSymlink(filePath, c.maxSymlinkDepth)
		if err != nil {
			log.Debug("Skipping symlink (resolution failed)", "filepath", filePath, "error", err)
			return nil, nil
		}
		info, err = os.Lstat(resolved)
		if err != nil {
			if os.IsNotExist(err) {
				log.Debug("Symlink target no longer exists", "filepath", filePath, "resolved", resolved)
				return nil, nil
			}
			return nil, fmt.Errorf("failed to stat symlink target %s: %w", resolved, err)
		}
		if !info.Mode().IsRegular() {
			log.Debug("Symlink target is not a regular file", "filepath", filePath, "resolved", resolved, "mode", info.Mode())
			return nil, nil
		}
		filePath = resolved
	}

	if !info.Mode().IsRegular() {
		return nil, nil
	}

	const maxRetries = 2
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := util.CheckContext(ctx); err != nil {
			return nil, err
		}

		results, scanErr := c.attemptScanFile(ctx, filePath, info.Size())
		if scanErr == nil {
			return results, nil
		}

		lastErr = scanErr

		if !isConnFatal(scanErr) {
			return nil, fmt.Errorf("failed to scan file %s: %w", filePath, scanErr)
		}

		log.Debug("Connection error during scan, draining pool and retrying",
			"file", filePath, "attempt", attempt, "max", maxRetries, "error", scanErr)

		c.drainPool()

		if attempt < maxRetries {
			timer := time.NewTimer(time.Second)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("failed to scan file %s after %d attempts: %w", filePath, maxRetries, lastErr)
}

// attemptScanFile performs a single attempt to scan a file.
func (c *Client) attemptScanFile(ctx context.Context, filePath string, fileSize int64) ([]*scanner.ScanResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsPermission(err) {
			log.Warn("Permission denied to open file", "filepath", filePath, "error", err)
			return nil, nil
		}

		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	conn, err := c.getConn(ctx)
	if err != nil {
		return nil, err
	}

	reInfo, reErr := os.Lstat(filePath)
	if reErr != nil {
		if os.IsNotExist(reErr) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to re-stat file %s: %w", filePath, reErr)
	}
	if reInfo.Mode()&os.ModeSymlink != 0 {
		resolved, resErr := util.ResolveSymlink(filePath, c.maxSymlinkDepth)
		if resErr != nil {
			return nil, nil
		}
		reInfo, resErr = os.Lstat(resolved)
		if resErr != nil || !reInfo.Mode().IsRegular() {
			return nil, nil
		}
		filePath = resolved
	}
	if !reInfo.Mode().IsRegular() {
		return nil, nil
	}

	connHealthy := false
	defer func() {
		if connHealthy {
			c.releaseConn(conn)
		} else {
			if closeErr := conn.Close(); closeErr != nil {
				log.Debug("Failed to close unhealthy connection", "error", closeErr)
			}
		}
	}()

	reqPayload := protocol.EncodeScanRequest(&protocol.ScanRequestHeader{
		FilePath: filePath,
		FileSize: fileSize,
	})

	if err := protocol.WriteFrame(conn, protocol.MsgScanRequest, reqPayload); err != nil {
		return nil, fmt.Errorf("failed to send scan request for %s: %w", filePath, err)
	}

	// Stream file data in chunks using pooled buffer
	bufPtr := scanBufPool.Get().(*[]byte)
	defer scanBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		default:
		}

		n, readErr := file.Read(buf)
		if n > 0 {
			conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
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

	// Scan completed successfully — connection is healthy and can be reused
	connHealthy = true

	if !resultMsg.Matched {
		return nil, nil
	}

	// Convert protocol.ScanResultEntry back to scanner.ScanResults
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
		return fmt.Errorf("failed to dial DBS for reload: %w", err)
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

// Status requests engine statistics from the DBS server and returns them.
func (c *Client) Status(ctx context.Context) (*protocol.StatusData, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to dial DBS for status: %w", err)
	}
	defer conn.Close()

	if err := protocol.WriteFrame(conn, protocol.MsgStatusRequest, nil); err != nil {
		return nil, fmt.Errorf("failed to send status request: %w", err)
	}

	msgType, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read status response: %w", err)
	}

	if msgType == protocol.MsgError {
		return nil, fmt.Errorf("DBS status request failed: %s", string(payload))
	}

	if msgType != protocol.MsgStatusResponse {
		return nil, fmt.Errorf("unexpected response to status request: 0x%02x", msgType)
	}

	return protocol.DecodeStatusData(payload)
}
