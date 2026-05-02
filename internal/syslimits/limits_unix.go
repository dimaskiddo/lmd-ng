//go:build unix

package syslimits

import (
	"syscall"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// SetMaxOpenFiles attempts to raise the maximum number of open files (RLIMIT_NOFILE)
// to its highest possible value to prevent "too many open files" errors during
// heavy scanning or monitoring on Unix systems (macOS, Linux).
func SetMaxOpenFiles() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		log.Warn("Failed to get RLIMIT_NOFILE", "error", err)
		return
	}

	// Try to set the soft limit to the hard limit.
	desired := rLimit.Max
	rLimit.Cur = desired

	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		// On some systems (especially macOS), setting the limit to Max might fail
		// with "invalid argument" if Max is "infinity" (e.g. INT64_MAX).
		// We fallback to known high sensible limits.
		fallbacks := []uint64{524288, 262144, 100000, 65535, 24576, 10240, 8192}

		success := false
		for _, fallback := range fallbacks {
			// Don't try to set a fallback higher than the hard limit (if it's a real number)
			// A value with the MSB set often represents infinity. We assume reasonable hard limits.
			if rLimit.Max != 0 && rLimit.Max != 9223372036854775807 && rLimit.Max < fallback {
				continue
			}

			rLimit.Cur = fallback
			if errFallback := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); errFallback == nil {
				log.Debug("Successfully increased open file limit via fallback", "limit", rLimit.Cur)
				success = true
				break
			}
		}

		if !success {
			log.Warn("Failed to increase RLIMIT_NOFILE even with fallbacks", "error", err, "max_limit", desired)
		}
	} else {
		log.Debug("Successfully increased open file limit", "limit", rLimit.Cur)
	}
}
