//go:build !windows

package service

import (
	"fmt"
	"os"

	kservice "github.com/kardianos/service"
)

// applyPlatformConfig applies Unix (Linux / macOS) specific settings to the
// kardianos/service Config.
//
// On POSIX systems:
//
//   - An empty UserName causes the service manager (systemd, launchd, OpenRC,
//     SysV) to run the process as root by default when installed system-wide.
//     We leave UserName empty rather than hardcoding "root" so that the
//     underlying service manager retains its natural, privileged default and
//     we avoid any confusion on non-Linux systems where the account name may
//     differ (e.g. macOS uses "root" too, but the intent is clearer this way).
//
//   - Restart=always (systemd) ensures the daemon is automatically restarted
//     if it crashes, matching the resilience expectations of a security tool.
//
//   - LimitNOFILE raises the open-file descriptor limit so that large directory
//     trees and concurrent scan workers don't hit the default system ulimit.
func applyPlatformConfig(cfg *kservice.Config) {
	// Leave UserName empty → service manager defaults to root for system-wide
	// services. Explicitly setting "root" is redundant and can cause issues
	// with non-systemd init systems (OpenRC, SysV) that handle User= differently.
	cfg.UserName = ""

	cfg.Option = kservice.KeyValue{
		"Restart":      "always",   // Restart the service automatically on any non-zero exit code.
		"LimitNOFILE":  "infinity", // Raise the open-file descriptor ceiling for large scans.
		"LimitNPROC":   "infinity", // Raise the open process limit for multi theread process.
		"LimitMEMLOCK": "infinity", // Raise the memory lock limit for large scans.
		"LimitCORE":    0,          // Disable core dump.
	}
}

// checkPrivilege verifies that the current process is running as root (UID 0).
// Service installation and removal require root privileges on Unix systems.
func checkPrivilege() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("%w (current UID: %d)", ErrInsufficientPrivilege, os.Getuid())
	}

	return nil
}
