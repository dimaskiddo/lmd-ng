package upgrade

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ReplaceBinary replaces the executable at exePath with the file at newBinaryPath.
// On Linux and macOS, this uses os.Rename for an atomic inode swap: the old inode
// stays valid for any process still holding it, while new invocations pick up the
// new inode. Falls back to copy+chmod for cross-device rename (EXDEV).
//
// The services parameter is ignored on Unix — services are managed by the CLI
// layer using the service package.
func ReplaceBinary(exePath, newBinaryPath string, services []string) error {
	// Backup old binary
	if err := os.Rename(exePath, exePath+".old"); err != nil {
		return fmt.Errorf("failed to backup old binary to %s: %w", exePath+".old", err)
	}

	// Move new binary to exePath — atomic on same filesystem
	if err := os.Rename(newBinaryPath, exePath); err != nil {
		if isCrossDeviceLink(err) {
			// Cross-filesystem fallback: copy + chmod
			if err := copyFile(newBinaryPath, exePath); err != nil {
				return fmt.Errorf("failed to copy binary to %s: %w", exePath, err)
			}
		} else {
			return fmt.Errorf("failed to move new binary to %s: %w", exePath, err)
		}
	}

	if err := os.Chmod(exePath, 0o755); err != nil {
		return fmt.Errorf("failed to chmod 0755 %s: %w", exePath, err)
	}

	return nil
}

// isCrossDeviceLink checks if an error is EXDEV (cross-device link).
func isCrossDeviceLink(err error) bool {
	var linkErr *os.LinkError
	if errors.As(err, &linkErr) {
		return errors.Is(linkErr.Err, syscall.EXDEV)
	}
	return false
}
