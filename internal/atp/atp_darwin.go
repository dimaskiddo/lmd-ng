//go:build darwin

package atp

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// SF_IMMUTABLE is 0x00020000 on macOS. Not exported by vendored unix darwin consts.
const sfImmutable = 0x00020000

// sysChflags is the __NR_chflags syscall number, 34 on amd64 and arm64 macOS.
const sysChflags = 34

// applyProtection sets SF_IMMUTABLE on every protected file.
func (p *Protector) applyProtection(files []string) error {
	var errs []error
	for _, f := range files {
		if err := setSFImmutable(f); err != nil {
			if os.IsNotExist(err) {
				log.Debug("ATP: skipping non-existent file", "file", f)
				continue
			}
			log.Warn("ATP: cannot set SF_IMMUTABLE (unsupported filesystem?)",
				"file", f, "error", err)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to protect %d files: %w", len(errs), errs[0])
	}
	return nil
}

// removeProtection clears SF_IMMUTABLE on all protected files.
func (p *Protector) removeProtection(files []string) error {
	for _, f := range files {
		if err := clearSFImmutable(f); err != nil {
			log.Warn("ATP: failed to clear SF_IMMUTABLE",
				"file", f, "error", err)
		}
	}
	log.Info("ATP: released all SF_IMMUTABLE flags")
	return nil
}

// setSFImmutable sets the SF_IMMUTABLE flag via a raw chflags syscall.
func setSFImmutable(path string) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	if _, _, errno := syscall.Syscall(sysChflags, uintptr(unsafe.Pointer(p)), sfImmutable, 0); errno != 0 {
		return fmt.Errorf("chflags SF_IMMUTABLE: %w", errno)
	}
	log.Debug("ATP: SF_IMMUTABLE set", "file", path)
	return nil
}

// clearSFImmutable clears SF_IMMUTABLE (chflags value 0 restores to normal).
func clearSFImmutable(path string) error {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return err
	}
	if _, _, errno := syscall.Syscall(sysChflags, uintptr(unsafe.Pointer(p)), 0, 0); errno != 0 {
		return fmt.Errorf("chflags clear SF_IMMUTABLE: %w", errno)
	}
	log.Debug("ATP: SF_IMMUTABLE cleared", "file", path)
	return nil
}

// isSFImmutableSet reports whether SF_IMMUTABLE is set on a file.
// Reads the fl_flags field via the stat structure.
func isSFImmutableSet(path string) bool {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return false
	}
	var st syscall.Stat_t
	if _, _, errno := syscall.Syscall(syscall.SYS_STAT, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&st)), 0); errno != 0 {
		return false
	}
	return uint32(st.Flags)&sfImmutable != 0
}

// recheckFiles re-applies SF_IMMUTABLE if it was cleared.
func (p *Protector) recheckFiles(files []string) {
	for _, f := range files {
		if isSFImmutableSet(f) {
			continue
		}
		log.Warn("ATP: SF_IMMUTABLE was cleared — re-applying", "file", f)
		if err := setSFImmutable(f); err != nil {
			log.Error("ATP: failed to re-apply SF_IMMUTABLE", "file", f, "error", err)
		}
	}
}

// startMonitor is a no-op on macOS.
func (p *Protector) startMonitor(ctx context.Context, files []string, control <-chan string) {
	log.Debug("ATP: macOS — no permission listener needed (SF_IMMUTABLE covers it)")
	<-ctx.Done()
}
