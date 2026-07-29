package upgrade

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// ReplaceBinary handles the Windows case where the running .exe is locked by
// the OS loader. It copies the new binary alongside the executable, writes a
// batch trampoline script, and launches it detached.
//
// The services parameter lists OS service names to restart after replacement
// (e.g. "lmd-ng-dbs", "lmd-ng-rtp"). If empty, the batch script skips
// service management and only replaces the binary.
//
// The batch script:
//  1. Waits 2 seconds for the old process to exit and release the file lock
//  2. Moves the new binary over the old one (move /Y)
//  3. Starts the listed services via sc start
//  4. Self-deletes
func ReplaceBinary(exePath, newBinaryPath string, services []string) error {
	exeDir := filepath.Dir(exePath)
	exeName := filepath.Base(exePath)
	newExeName := exeName + ".new"
	batPath := filepath.Join(exeDir, "upgrade-finalize.bat")

	// Copy new binary to .new alongside the executable
	newTarget := filepath.Join(exeDir, newExeName)
	if err := copyFile(newBinaryPath, newTarget); err != nil {
		return fmt.Errorf("failed to copy new binary to %s: %w", newTarget, err)
	}

	// Build batch script content
	var bat strings.Builder
	bat.WriteString("@echo off\n")
	bat.WriteString("timeout /t 2 /nobreak >nul\n")
	fmt.Fprintf(&bat, "move /Y \"%s\" \"%s\"\n", newExeName, exeName)

	for _, svc := range services {
		fmt.Fprintf(&bat, "sc start %s\n", svc)
	}

	fmt.Fprintf(&bat, "del \"%s\"\n", batPath)

	if err := os.WriteFile(batPath, []byte(bat.String()), 0o755); err != nil {
		os.Remove(newTarget)
		return fmt.Errorf("failed to write batch trampoline: %w", err)
	}

	// Execute batch script detached
	batCmd := exec.Command("cmd", "/c", "start", "", batPath)
	batCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := batCmd.Start(); err != nil {
		os.Remove(batPath)
		os.Remove(newTarget)
		return fmt.Errorf("failed to start batch trampoline: %w", err)
	}

	// Detach — don't wait for it
	_ = batCmd.Process.Release()

	return nil
}
