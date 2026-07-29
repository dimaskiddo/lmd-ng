//go:build !windows

package util

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// resolvedTempDirs are the real paths for system temp directories, resolved
// once at init to handle macOS's /tmp → /private/tmp symlink and similar.
var resolvedTempDirs = initTempDirs()

func initTempDirs() []string {
	var dirs []string
	for _, raw := range []string{"/tmp", "/var/tmp"} {
		if real, err := filepath.EvalSymlinks(raw); err == nil {
			dirs = append(dirs, real)
		} else {
			dirs = append(dirs, raw)
		}
	}
	return dirs
}

// IsOrphanTempPath checks if path is a #-prefixed file in a system temp directory.
// Pure path-string check — no stat required. Safe to call even when file is deleted.
func IsOrphanTempPath(path string) bool {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "#") {
		return false
	}

	dir := filepath.Clean(filepath.Dir(path))
	for _, tmpDir := range resolvedTempDirs {
		if dir == tmpDir || strings.HasPrefix(dir, tmpDir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// IsOrphanTempFile returns true if the file is an orphan inode (Nlink == 0)
// or a known system-tool temp artifact under /tmp or /var/tmp.
//
// Nlink == 0 means the file was unlinked from its directory entry while
// a file descriptor is still open. Such files are held alive only by the
// kernel — they cannot be executed, renamed, or hard-linked. Skipping them
// is unconditionally safe and cannot be evaded by malware.
func IsOrphanTempFile(path string, info os.FileInfo) bool {
	// Check Nlink first — the inode-level guarantee
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink == 0 {
		return true
	}

	return IsOrphanTempPath(path)
}
