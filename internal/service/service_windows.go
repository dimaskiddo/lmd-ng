//go:build windows

package service

import (
	"fmt"

	kservice "github.com/kardianos/service"
	"golang.org/x/sys/windows"
)

// applyPlatformConfig applies Windows-specific settings to the
// kardianos/service Config.
//
// On Windows:
//
//   - An empty UserName (ServiceStartName) causes the SCM to run the service
//     under the built-in LocalSystem account, which is the highest-privilege
//     account available on Windows and the correct choice for a system-wide
//     security tool. Do NOT set UserName to "root" — that account does not
//     exist on Windows and will cause the SCM to reject the installation.
//
//   - StartType=automatic ensures the service starts at boot without operator
//     intervention, matching the behaviour of the original LMD cron job.
//
//   - OnFailure=restart with a short delay mirrors the systemd Restart=always
//     behaviour to keep the daemon resilient against crashes.
func applyPlatformConfig(cfg *kservice.Config) {
	// Empty string → LocalSystem account (highest privilege on Windows).
	cfg.UserName = ""

	cfg.Option = kservice.KeyValue{
		"StartType":              "automatic", // Start automatically at boot.
		"OnFailure":              "restart",   // Restart the service 5 seconds after a crash.
		"OnFailureDelayDuration": "5s",        // Delay before restarting the service.
		"OnFailureResetPeriod":   60,          // Reset the failure counter after 60 seconds of clean operation.
	}
}

// checkPrivilege verifies that the current process token has the
// SeDebugPrivilege or, more practically, that the process is a member of the
// local Administrators group. Installing/removing Windows services via the SCM
// always requires Administrator rights regardless of the token elevation state.
func checkPrivilege() error {
	// windows.Token(0) refers to the current process token.
	token := windows.Token(0)

	elevated := token.IsElevated()
	if !elevated {
		return fmt.Errorf("%w: re-run as Administrator or with UAC elevation", ErrInsufficientPrivilege)
	}

	return nil
}
