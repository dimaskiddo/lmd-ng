//go:build linux

package atp

import (
	"os"
	"strings"
)

// SelfExeDeleted reports whether the running binary's inode was replaced
// after process start, detected via the " (deleted)" suffix on
// /proc/self/exe (documented in proc(5)). Exported for status reporting.
func SelfExeDeleted() bool {
	return selfExeDeleted()
}

// selfExeDeleted is the internal implementation of SelfExeDeleted.
func selfExeDeleted() bool {
	link, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return false
	}
	return strings.HasSuffix(link, " (deleted)")
}
