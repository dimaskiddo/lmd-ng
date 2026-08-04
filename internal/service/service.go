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
	// ComponentATP is the Anti-Tamper Protection daemon. It locks LMD-NG's
	// critical files against modification/deletion and runs as lmd-ng-atp.
	ComponentATP Component = "atp"

	// ComponentDBS is the Database Signature Service (server).
	ComponentDBS Component = "dbs"

	// ComponentRTP is the Real-Time Protector (client).
	ComponentRTP Component = "rtp"

	// legacyServiceName is the old monolithic service name used before the
	// client-server split. This is auto-uninstalled during migration.
	legacyServiceName = "lmd-ng"
)

// DependencyOrder lists components in startup order: ATP first (locks critical
// files), then DBS (loads signatures), then RTP (connects to DBS).
var DependencyOrder = []Component{ComponentATP, ComponentDBS, ComponentRTP}

// Dependencies maps each component to the set of services that must be running
// before it can start. ATP protects files first; DBS requires the files it
// reads (signatures, TLS certs) to be locked; RTP requires a live DBS server.
var Dependencies = map[Component][]Component{
	ComponentATP: {},
	ComponentDBS: {ComponentATP},
	ComponentRTP: {ComponentATP, ComponentDBS},
}

// ErrInsufficientPrivilege is returned when the caller does not have the
// required elevated privileges to install or uninstall a system service.
var ErrInsufficientPrivilege = errors.New("insufficient privileges: service management requires root (Linux/macOS) or Administrator (Windows) access")

// LMDService implements kservice.Interface. Actual daemon logic runs via the
// "lmd-ng daemon <component>" subcommand invoked through Arguments.
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
	case ComponentATP:
		return "LMD-NG Anti-Tamper Protection"

	case ComponentDBS:
		return "LMD-NG Database Signature Service"

	case ComponentRTP:
		return "LMD-NG Real-Time Protector"

	default:
		return fmt.Sprintf("LMD-NG %s", comp)
	}
}

// buildServiceConfig constructs the kardianos/service Config, baking the
// component's --service, --config, and --log-file flags into Arguments.
func buildServiceConfig(exePath string, comp Component, cfgPath, logFilePath string) *kservice.Config {
	args := []string{"daemon", string(comp), "--service"}
	if cfgPath != "" {
		args = append(args, "--config", cfgPath)
	}
	if logFilePath != "" {
		args = append(args, "--log-file", logFilePath)
	}

	cfg := &kservice.Config{
		Name:             serviceName(comp),
		DisplayName:      displayName(comp),
		Description:      fmt.Sprintf("Linux Malware Detect Next Generation (LMD-NG) - %s", displayName(comp)),
		WorkingDirectory: filepath.Dir(exePath),
		Arguments:        args,
	}

	applyPlatformConfig(cfg)

	// Restart ATP promptly so protected files are never left unwatched.
	if comp == ComponentATP {
		if cfg.Option == nil {
			cfg.Option = kservice.KeyValue{}
		}
		cfg.Option["WatchdogSec"] = 60
	}

	return cfg
}

// UninstallLegacyService removes the old monolithic "lmd-ng" service. Idempotent.
func UninstallLegacyService() error {
	if err := checkPrivilege(); err != nil {
		return fmt.Errorf("uninstall legacy service: %w", err)
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

	log.Info("Migrating legacy monolithic service", "service", legacyServiceName, "status", status)

	// Stop the legacy service (best-effort)
	if err := svc.Stop(); err != nil {
		log.Warn("Failed to stop legacy service during migration", "service", legacyServiceName, "error", err)
	}

	// Uninstall the legacy service
	if err := svc.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall legacy service %s: %w", legacyServiceName, err)
	}

	log.Info("Legacy service uninstalled successfully", "service", legacyServiceName)
	return nil
}

// InstallService installs a specific component as an OS-level system service.
// exePath is the binary to register (the running executable when empty).
// cfgPath is the resolved config file path baked into the service arguments
// (empty to rely on auto-discovery). logFilePath is the component log path.
func InstallService(exePath, cfgPath, logFilePath string, comp Component) error {
	if err := checkPrivilege(); err != nil {
		return fmt.Errorf("install service %s: %w", comp, err)
	}

	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return fmt.Errorf("failed to resolve executable path: %w", err)
		}
	}

	svcConfig := buildServiceConfig(exePath, comp, cfgPath, logFilePath)

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
		return fmt.Errorf("uninstall service %s: %w", comp, err)
	}

	svcConfig := &kservice.Config{Name: serviceName(comp)}

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle for %s: %w", comp, err)
	}

	// Stop is best-effort; a stopped service can still be uninstalled cleanly.
	if err := svc.Stop(); err != nil {
		log.Warn("Failed to stop service before uninstall", "service", comp, "error", err)
	}

	if err = svc.Uninstall(); err != nil {
		return fmt.Errorf("failed to uninstall service %s: %w", comp, err)
	}

	return nil
}

// StartService starts a specific component's system service.
func StartService(_ *config.Config, comp Component) error {
	if err := checkPrivilege(); err != nil {
		return fmt.Errorf("start service %s: %w", comp, err)
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
		return fmt.Errorf("stop service %s: %w", comp, err)
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
		return fmt.Errorf("restart service %s: %w", comp, err)
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

// IsServiceInstalled checks whether an OS service with the given component
// name is currently installed. It does not require elevated privileges.
func IsServiceInstalled(comp Component) bool {
	svcConfig := &kservice.Config{Name: serviceName(comp)}

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return false
	}

	_, err = svc.Status()
	return err == nil
}

// StatusService reports the current OS service status for a component. It
// requires elevated privileges to query.
func StatusService(_ *config.Config, comp Component) (*kservice.Status, error) {
	if err := checkPrivilege(); err != nil {
		return nil, fmt.Errorf("status service %s: %w", comp, err)
	}

	svcConfig := &kservice.Config{Name: serviceName(comp)}
	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create service handle for %s: %w", comp, err)
	}

	status, err := svc.Status()
	if err != nil {
		return nil, fmt.Errorf("failed to get status for %s: %w", comp, err)
	}

	return &status, nil
}
