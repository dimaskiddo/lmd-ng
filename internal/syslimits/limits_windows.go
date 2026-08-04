//go:build windows

package syslimits

import (
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// SetMaxOpenFiles is a no-op on Windows, which does not use RLIMIT_NOFILE.
func SetMaxOpenFiles() {
	log.Debug("SetMaxOpenFiles is not applicable on Windows (No Fixed Limit)")
}
