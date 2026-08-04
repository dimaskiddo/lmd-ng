//go:build windows

package scanner

import (
	"os"

	"github.com/dimaskiddo/lmd-ng/internal/config"
)

// applyOwnerFilters is a no-op on Windows (no Unix UID/GID semantics).
func applyOwnerFilters(_ string, _ os.FileInfo, _ *config.Config) bool {
	return false
}
