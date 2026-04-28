package service

import (
	"fmt"
	"os"
	"path/filepath"

	kservice "github.com/kardianos/service"

	"github.com/dimaskiddo/lmd-ng/internal/config"
)

type LMDService struct{}

// Start is called by kardianos/service
func (s *LMDService) Start(svc kservice.Service) error {
	return nil
}

// Stop is called by kardianos/service
func (s *LMDService) Stop(svc kservice.Service) error {
	return nil
}

// InstallService installs LMD-NG as an OS-level service.
func InstallService(cfg *config.Config) error {
	// The service command will be the current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	svcConfig := &kservice.Config{
		Name:             "lmd-ng",
		DisplayName:      "LMD-NG Resident Monitoring",
		Description:      "Linux Malware Detect Next Generation (LMD-NG)",
		UserName:         "root",
		WorkingDirectory: filepath.Dir(exePath),
		Arguments:        []string{"daemon"},
	}

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle for install: %w", err)
	}

	err = svc.Install()
	if err != nil {
		return fmt.Errorf("failed to install service: %w", err)
	}

	err = svc.Start()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	return nil
}

// UninstallService uninstalls the LMD-NG OS-level service.
func UninstallService(cfg *config.Config) error {
	svcConfig := &kservice.Config{
		Name: "lmd-ng",
	}

	svc, err := kservice.New(&LMDService{}, svcConfig)
	if err != nil {
		return fmt.Errorf("failed to create service handle for uninstall: %w", err)
	}

	_ = svc.Stop()

	err = svc.Uninstall()
	if err != nil {
		return fmt.Errorf("failed to uninstall service: %w", err)
	}

	return nil
}
