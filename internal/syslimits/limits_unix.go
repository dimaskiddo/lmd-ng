//go:build unix

package syslimits

import (
	"syscall"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// SetMaxOpenFiles raises RLIMIT_NOFILE to its maximum to prevent "too many
// open files" errors during heavy scanning on Unix systems.
func SetMaxOpenFiles() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		log.Warn("Failed to get RLIMIT_NOFILE", "error", err)
		return
	}

	desired := rLimit.Max
	rLimit.Cur = desired

	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit); err != nil {
		fallbacks := []uint64{
			8192000, 4096000, 2048000, 1024000,
			819200, 409600, 204800, 102400,
			81920, 40960, 20480, 10240,
			8192, 4096, 2048, 1024,
		}

		success := false
		for _, fallback := range fallbacks {
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
