//go:build windows

package util

import (
	"os"
	"path/filepath"
	"strings"
)

// IsOrphanTempPath checks if path is a #-prefixed file in a system temp directory.
// Pure path-string check — no stat required. Safe to call even when file is deleted.
func IsOrphanTempPath(path string) bool {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "#") {
		return false
	}

	dir := filepath.Clean(filepath.Dir(path))
	tmpDir := filepath.Clean(os.TempDir())
	return dir == tmpDir || strings.HasPrefix(dir, tmpDir+string(filepath.Separator))
}

// IsOrphanTempFile returns true for #* basename files in Windows temp directories.
// Nlink does not exist on Windows; the basename heuristic is the best available signal.
func IsOrphanTempFile(path string, _ os.FileInfo) bool {
	return IsOrphanTempPath(path)
}
