//go:build windows

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
// the OS loader. It stages the new binary and uses a detached batch trampoline
// to swap it over and restart the listed services.
func ReplaceBinary(exePath, newBinaryPath string, services []string) error {
	exeDir := filepath.Dir(exePath)
	exeName := filepath.Base(exePath)
	newExeName := exeName + ".new"
	batPath := filepath.Join(exeDir, "upgrade-finalize.bat")

	newTarget := filepath.Join(exeDir, newExeName)
	if err := copyFile(newBinaryPath, newTarget); err != nil {
		return fmt.Errorf("failed to copy new binary to %s: %w", newTarget, err)
	}

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

	batCmd := exec.Command("cmd", "/c", "start", "", batPath)
	batCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	if err := batCmd.Start(); err != nil {
		os.Remove(batPath)
		os.Remove(newTarget)
		return fmt.Errorf("failed to start batch trampoline: %w", err)
	}

	_ = batCmd.Process.Release()

	return nil
}
