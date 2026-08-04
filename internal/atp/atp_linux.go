//go:build linux

package atp

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/dimaskiddo/lmd-ng/internal/log"
	"golang.org/x/sys/unix"
)

// ext2IMMUTABLEFL is the FS_IMMUTABLE_FL inode flag (`chattr +i`).
const ext2IMMUTABLEFL = 0x00000010

// applyProtection sets the immutable flag on every protected file.
func (p *Protector) applyProtection(files []string) error {
	var errs []error
	for _, f := range files {
		if err := setImmutable(f); err != nil {
			if os.IsNotExist(err) {
				log.Debug("ATP: skipping non-existent file", "file", f)
				continue
			}
			log.Warn("ATP: cannot set immutable flag (unsupported filesystem?)",
				"file", f, "error", err)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("failed to protect %d files: %w", len(errs), errors.Join(errs...))
	}
	return nil
}

// removeProtection clears the immutable flag on all protected files.
func (p *Protector) removeProtection(files []string) error {
	for _, f := range files {
		if isImmutableSet(f) {
			if err := clearImmutable(f); err != nil {
				log.Warn("ATP: failed to clear immutable flag",
					"file", f, "error", err)
			}
		}
	}
	log.Info("ATP: released all immutable flags")
	return nil
}

// setImmutable sets FS_IMMUTABLE_FL on the file via ioctl.
func setImmutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var flags int32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		uintptr(unix.FS_IOC_GETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("ioctl FS_IOC_GETFLAGS: %w", errno)
	}

	flags |= ext2IMMUTABLEFL
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		uintptr(unix.FS_IOC_SETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("ioctl FS_IOC_SETFLAGS: %w", errno)
	}

	log.Debug("ATP: +i set", "file", path)
	return nil
}

// clearImmutable removes FS_IMMUTABLE_FL from the file.
func clearImmutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var flags int32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		uintptr(unix.FS_IOC_GETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("ioctl FS_IOC_GETFLAGS: %w", errno)
	}

	flags &^= ext2IMMUTABLEFL
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		uintptr(unix.FS_IOC_SETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return fmt.Errorf("ioctl FS_IOC_SETFLAGS (clear): %w", errno)
	}

	log.Debug("ATP: +i cleared", "file", path)
	return nil
}

// isImmutableSet reports whether FS_IMMUTABLE_FL is currently set on a file.
func isImmutableSet(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var flags int32
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(),
		uintptr(unix.FS_IOC_GETFLAGS), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return false
	}
	return flags&ext2IMMUTABLEFL != 0
}

// recheckFiles re-applies the immutable flag if it was cleared.
func (p *Protector) recheckFiles(files []string) {
	for _, f := range files {
		if isImmutableSet(f) {
			continue
		}
		log.Warn("ATP: immutable flag was cleared — re-applying", "file", f)
		if err := setImmutable(f); err != nil {
			log.Error("ATP: failed to re-apply immutable flag", "file", f, "error", err)
		}
	}
}
