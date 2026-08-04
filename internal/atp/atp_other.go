//go:build !linux && !darwin && !windows

package atp

import (
	"context"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// applyProtection is a no-op on unsupported platforms.
func (p *Protector) applyProtection(files []string) error {
	log.Info("ATP: no active protection available on this platform")
	return nil
}

func (p *Protector) removeProtection(files []string) error { return nil }

func (p *Protector) recheckFiles(files []string) {}

func (p *Protector) startMonitor(ctx context.Context, files []string, control <-chan string) {
	<-ctx.Done()
}

func isImmutableSet(path string) bool { return false }
