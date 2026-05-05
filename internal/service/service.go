package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	kservice "github.com/kardianos/service"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// Component represents a daemon component that can be managed as a service.
type Component string

const (
	// ComponentDBS is the Database Signature Service (server).
	ComponentDBS Component = "dbs"

	// ComponentRTP is the Real-Time Protector (client).
	ComponentRTP Component = "rtp"

	// legacyServiceName is the old monolithic service name used before the
	// client-server split. This is auto-uninstalled during migration.
	legacyServiceName = "lmd-ng"
)

// ErrInsufficientPrivilege is returned when the caller does not have the
// required elevated privileges to install or uninstall a system service.
var ErrInsufficientPrivilege = errors.New("insufficient privileges: service management requires root (Linux/macOS) or Administrator (Windows) access")

// LMDService implements kservice.Interface. Start and Stop are intentionally
// minimal stubs; the actual daemon logic is driven by the "lmd-ng daemon <component>"
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

// serviceName returns the OS service name for the given component.
func serviceName(comp Component) string {
	return fmt.Sprintf("lmd-ng-%s", comp)
}

// displayName returns a human-readable display name for the given component.
func displayName(comp Component) string {
	switch comp {
	case ComponentDBS:
		return "LMD-NG Database Signature Service"

	case ComponentRTP:
		return "LMD-NG Real-Time Protector"

	default:
		return fmt.Sprintf("LMD-NG %s", comp)
	}
}

// AllComponents returns all components in install/start order (DBS first, then RTP).
func AllComponents() []Component {
	return []Component{ComponentDBS, ComponentRTP}
}

// buildServiceConfig constructs the kardianos/service Config for a specific component.
func buildServiceConfig(exePath string, comp Component) *kservice.Config {
	cfg := &kservice.Config{
		Name:             serviceName(comp),
		DisplayName:      displayName(comp),
		Description:      fmt.Sprintf("Linux Malware Detect Next Generation (LMD-NG) - %s", displayName(comp)),
		WorkingDirectory: filepath.Dir(exePath),
		Arguments:        []string{"daemon", string(comp)},
	}

	// Delegate platform-specific privilege and option population.
	applyPlatformConfig(cfg)

	return cfg
}

// UninstallLegacyService detects and removes the old monolithic "lmd-ng" service.
// This is called automatically during `service install` to migrate from the old
// single-service model to the new DBS/RTP split. The function is idempotent —
// it returns nil if the legacy service doesn't exist.
func UninstallLegacyService() error {
	if err := checkPrivilege(); err != nil {
		return err
	}

	svcConfig := &kservice.Config{Name: legacyServiceName}

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create legacy service handle: %w", err)
	}

	// Check if the legacy service exists by attempting to query its status.
	// If it doesn't exist, the Status() call will fail — that's fine.
	status, err := svc.Status()
	if err != nil {
		// Service doesn't exist or can't be queried — nothing to migrate
		log.Debug("Legacy service not found, no migration needed", "service", legacyServiceName)
		return nil
	}

	log.Info("Legacy monolithic service detected, migrating...", "service", legacyServiceName, "status", status)

	// Stop the legacy service (best-effort)
	_ = svc.Stop()

	// Uninstall the legacy service
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall legacy service %s: %w", legacyServiceName, err)
	}

	log.Info("Legacy service uninstalled successfully", "service", legacyServiceName)
	return nil
}

// InstallService installs a specific component as an OS-level system service.
func InstallService(_ *config.Config, comp Component) error {
	if err := checkPrivilege(); err != nil {
		return err
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to resolve executable path: %w", err)
	}

	svcConfig := buildServiceConfig(exePath, comp)

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle for %s: %w", comp, err)
	}

	if err = svc.Install(); err != nil {
		return fmt.Errorf("failed to install service %s: %w", comp, err)
	}

	return nil
}

// UninstallService stops and removes a specific component's system service.
func UninstallService(_ *config.Config, comp Component) error {
	if err := checkPrivilege(); err != nil {
		return err
	}

	svcConfig := &kservice.Config{Name: serviceName(comp)}

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle for %s: %w", comp, err)
	}

	// Stop is best-effort; a stopped service can still be uninstalled cleanly.
	_ = svc.Stop()

	if err = svc.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall service %s: %w", comp, err)
	}

	return nil
}

// StartService starts a specific component's system service.
func StartService(_ *config.Config, comp Component) error {
	if err := checkPrivilege(); err != nil {
		return err
	}

	svcConfig := &kservice.Config{Name: serviceName(comp)}
	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle for %s: %w", comp, err)
	}

	if err = svc.Start(); err != nil {
		return fmt.Errorf("failed to start service %s: %w", comp, err)
	}

	return nil
}

// StopService stops a specific component's system service.
func StopService(_ *config.Config, comp Component) error {
	if err := checkPrivilege(); err != nil {
		return err
	}

	svcConfig := &kservice.Config{Name: serviceName(comp)}
	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle for %s: %w", comp, err)
	}

	if err = svc.Stop(); err != nil {
		return fmt.Errorf("failed to stop service %s: %w", comp, err)
	}

	return nil
}

// RestartService restarts a specific component's system service.
func RestartService(_ *config.Config, comp Component) error {
	if err := checkPrivilege(); err != nil {
		return err
	}

	svcConfig := &kservice.Config{Name: serviceName(comp)}
	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle for %s: %w", comp, err)
	}

	if err = svc.Restart(); err != nil {
		return fmt.Errorf("failed to restart service %s: %w", comp, err)
	}

	return nil
}
