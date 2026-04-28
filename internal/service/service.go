package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	kservice "github.com/kardianos/service"

	"github.com/dimaskiddo/lmd-ng/internal/config"
)

// ErrInsufficientPrivilege is returned when the caller does not have the
// required elevated privileges to install or uninstall a system service.
var ErrInsufficientPrivilege = errors.New("insufficient privileges: service management requires root (Linux/macOS) or Administrator (Windows) access")

// LMDService implements kservice.Interface. Start and Stop are intentionally
// minimal stubs; the actual daemon logic is driven by the "lmd-ng daemon"
// subcommand that kardianos/service invokes through the Arguments field.
type LMDService struct{}

// Start is called by kardianos/service when the OS service manager starts the process.
func (s *LMDService) Start(svc kservice.Service) error {
	return nil
}

// Stop is called by kardianos/service when the OS service manager stops the process.
func (s *LMDService) Stop(svc kservice.Service) error {
	return nil
}

// buildServiceConfig constructs the kardianos/service Config with all
// production-hardening options. Platform-specific fields (UserName, Options)
// are populated by the platform-specific helpers defined in the build-tag files.
func buildServiceConfig(exePath string) *kservice.Config {
	cfg := &kservice.Config{
		Name:             "lmd-ng",
		DisplayName:      "LMD-NG Resident Monitoring",
		Description:      "Linux Malware Detect Next Generation (LMD-NG)",
		WorkingDirectory: filepath.Dir(exePath),
		Arguments:        []string{"daemon"},
	}

	// Delegate platform-specific privilege and option population.
	applyPlatformConfig(cfg)

	return cfg
}

// InstallService installs LMD-NG as a privileged OS-level system service and
// immediately starts it. The caller must already be running with elevated
// privileges (root on Linux/macOS, Administrator on Windows); otherwise the
// function returns ErrInsufficientPrivilege without attempting any OS changes.
func InstallService(_ *config.Config) error {
	if err := checkPrivilege(); err != nil {
		return err
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	svcConfig := buildServiceConfig(exePath)

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle: %w", err)
	}

	if err = svc.Install(); err != nil {
		return fmt.Errorf("failed to install service: %w", err)
	}

	if err = svc.Start(); err != nil {
		// The unit is already installed; surface the start error but do not
		// roll back the installation automatically — the operator can inspect
		// and start manually.
		return fmt.Errorf("service installed but failed to start: %w", err)
	}

	return nil
}

// UninstallService stops and removes the LMD-NG system service. The caller
// must already be running with elevated privileges; otherwise the function
// returns ErrInsufficientPrivilege without attempting any OS changes.
func UninstallService(_ *config.Config) error {
	if err := checkPrivilege(); err != nil {
		return err
	}

	svcConfig := &kservice.Config{
		Name: "lmd-ng",
	}

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle: %w", err)
	}

	// Stop is best-effort; a stopped service can still be uninstalled cleanly.
	_ = svc.Stop()

	if err = svc.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall service: %w", err)
	}

	return nil
}
