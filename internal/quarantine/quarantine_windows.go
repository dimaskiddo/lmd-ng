//go:build windows

package quarantine

import "os"

// captureOwnership is a no-op on Windows. Windows uses ACLs rather than
// POSIX UID/GID, so ownership capture is not supported.
func captureOwnership(info os.FileInfo) (uid, gid uint32, username, groupName string) {
	return 0, 0, "", ""
}

// applyOwnership is a no-op on Windows.
func applyOwnership(path string, uid, gid uint32) error {
	return nil
}
