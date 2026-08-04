//go:build windows

package service

import (
	"fmt"

	kservice "github.com/kardianos/service"
	"golang.org/x/sys/windows"
)

// applyPlatformConfig applies Windows-specific settings to the service Config.
func applyPlatformConfig(cfg *kservice.Config) {
	cfg.UserName = ""

	cfg.Option = kservice.KeyValue{
		"StartType":              "automatic",
		"OnFailure":              "restart",
		"OnFailureDelayDuration": "5s",
		"OnFailureResetPeriod":   60,
	}
}

// checkPrivilege verifies the process token is elevated.
func checkPrivilege() error {
	token := windows.Token(0)

	elevated := token.IsElevated()
	if !elevated {
		return fmt.Errorf("%w: re-run as Administrator or with UAC elevation", ErrInsufficientPrivilege)
	}

	return nil
}
