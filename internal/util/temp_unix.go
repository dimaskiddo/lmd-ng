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

// IsOrphanTempPath reports whether path is a #-prefixed file in a system temp dir.
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

// IsLockFilePath reports whether path is an editor/tool lock file (Emacs, GnuPG).
func IsLockFilePath(path string) bool {
	return strings.HasPrefix(filepath.Base(path), ".#")
}

// IsOrphanTempFile reports whether the file is an orphan inode (Nlink == 0) or a
// system-tool temp artifact under /tmp or /var/tmp.
func IsOrphanTempFile(path string, info os.FileInfo) bool {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink == 0 {
		return true
	}

	return IsOrphanTempPath(path)
}
