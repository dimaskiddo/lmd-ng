//go:build !windows

package util

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// IsOrphanTempFile returns true if the file is an orphan inode (Nlink == 0)
// or a known system-tool temp artifact under /tmp or /var/tmp.
//
// Nlink == 0 means the file was unlinked from its directory entry while
// a file descriptor is still open. Such files are held alive only by the
// kernel — they cannot be executed, renamed, or hard-linked. Skipping them
// is unconditionally safe and cannot be evaded by malware.
//
// As a practical noise-reduction heuristic, files with basename prefixed
// by "#" (vim/emacs autosave) in system temp directories are also skipped
// even when Nlink >= 1.
func IsOrphanTempFile(path string, info os.FileInfo) bool {
	// Check Nlink first — the inode-level guarantee
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Nlink == 0 {
		return true
	}

	// Practical heuristic: #* basename in system temp dirs
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "#") {
		return false
	}

	dir := filepath.Clean(filepath.Dir(path))
	return dir == "/tmp" || dir == "/var/tmp" ||
		strings.HasPrefix(dir, "/tmp"+string(filepath.Separator)) ||
		strings.HasPrefix(dir, "/var/tmp"+string(filepath.Separator))
}
