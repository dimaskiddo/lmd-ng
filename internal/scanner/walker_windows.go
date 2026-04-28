//go:build windows

package scanner

import (
	"os"

	"github.com/dimaskiddo/lmd-ng/internal/config"
)

// applyOwnerFilters on Windows is a no-op because Windows does not use
// Unix UID/GID ownership semantics. ignore_root, ignore_users, and
// ignore_groups filters are silently skipped on this platform.
func applyOwnerFilters(_ string, _ os.FileInfo, _ *config.Config) bool {
	return false
}
