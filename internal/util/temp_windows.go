//go:build windows

package util

import (
	"os"
	"path/filepath"
	"strings"
)

// IsOrphanTempFile returns true for #* basename files in Windows temp directories.
// Nlink does not exist on Windows; the basename heuristic is the best available signal.
func IsOrphanTempFile(path string, _ os.FileInfo) bool {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "#") {
		return false
	}

	dir := filepath.Clean(filepath.Dir(path))
	tmpDir := filepath.Clean(os.TempDir())
	return dir == tmpDir || strings.HasPrefix(dir, tmpDir+string(filepath.Separator))
}
