//go:build windows

package syslimits

import (
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// SetMaxOpenFiles on Windows is largely a no-op as Windows does not use
// RLIMIT_NOFILE. Go's file implementation uses native Win32 API handles
// which are limited only by system resources (typically up to 16M handles).
// If a "too many open files" error occurs on Windows, it indicates an actual
// handle leak rather than a low system limit.
func SetMaxOpenFiles() {
	log.Debug("SetMaxOpenFiles is not applicable on Windows (No Fixed Limit)")
}
