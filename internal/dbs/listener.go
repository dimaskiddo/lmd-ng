package dbs

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/protocol"
)

// NewListener creates a TLS-wrapped network listener based on the server
// configuration. Both Unix socket and TCP transports are always encrypted.
func NewListener(cfg *config.Config) (net.Listener, error) {
	certFile, keyFile, caFile := protocol.ServerCertPaths(cfg)

	tlsConfig, err := protocol.NewServerTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to create server TLS config: %w", err)
	}

	switch cfg.Server.Network {
	case "tcp":
		return newTCPListener(cfg.Server.Address, cfg.Server.SocketBacklog, tlsConfig)

	case "unix":
		return newUnixListener(cfg.Server.SocketPath, cfg.Server.SocketBacklog, tlsConfig)

	default:
		// Default to unix on non-Windows, tcp on Windows
		if runtime.GOOS == "windows" {
			return newTCPListener(cfg.Server.Address, cfg.Server.SocketBacklog, tlsConfig)
		}

		return newUnixListener(cfg.Server.SocketPath, cfg.Server.SocketBacklog, tlsConfig)
	}
}

// newTCPListener creates a TLS-wrapped TCP listener.
func newTCPListener(address string, backlog int, tlsConfig *tls.Config) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = setBacklog(fd, backlog)
			})
		},
	}

	rawLn, err := lc.Listen(context.Background(), "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TCP %s: %w", address, err)
	}

	tlsLn := tls.NewListener(rawLn, tlsConfig)

	log.Info("DBS server listening on TCP", "address", address, "backlog", backlog)
	return tlsLn, nil
}

// newUnixListener creates a TLS-wrapped Unix domain socket listener.
// It cleans up any stale socket file from a previous run before binding.
func newUnixListener(socketPath string, backlog int, tlsConfig *tls.Config) (net.Listener, error) {
	// Remove stale socket file if it exists from a previous run
	if _, err := os.Stat(socketPath); err == nil {
		// Attempt to connect — if we can, another instance is running
		testConn, dialErr := net.Dial("unix", socketPath)
		if dialErr == nil {
			testConn.Close()
			return nil, fmt.Errorf("another DBS instance appears to be running on socket %s", socketPath)
		}

		// Stale socket — remove it
		log.Debug("Removing stale Unix socket", "path", socketPath)
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("failed to remove stale socket %s: %w", socketPath, err)
		}
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				_ = setBacklog(fd, backlog)
			})
		},
	}

	rawLn, err := lc.Listen(context.Background(), "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on Unix socket %s: %w", socketPath, err)
	}

	// Set socket permissions to owner-only for security
	if err := os.Chmod(socketPath, 0600); err != nil {
		rawLn.Close()
		return nil, fmt.Errorf("failed to set permissions on socket %s: %w", socketPath, err)
	}

	// Wrap the Unix socket with TLS for encrypted communication
	tlsLn := tls.NewListener(rawLn, tlsConfig)

	log.Info("DBS server listening on Unix socket", "path", socketPath, "backlog", backlog)
	return tlsLn, nil
}
