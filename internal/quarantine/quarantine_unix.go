//go:build !windows

package quarantine

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// captureOwnership extracts the UID and GID from the file's os.FileInfo and
// attempts to resolve them to human-readable username and group name strings.
// On non-Unix systems this function is not compiled (see quarantine_windows.go).
func captureOwnership(info os.FileInfo) (uid, gid uint32, username, groupName string) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, "", ""
	}

	uid = stat.Uid
	gid = stat.Gid

	// Resolve UID to username — best effort; ignore lookup errors.
	if u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10)); err == nil {
		username = u.Username
	}

	// Resolve GID to group name — best effort; ignore lookup errors.
	if g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10)); err == nil {
		groupName = g.Name
	}

	return uid, gid, username, groupName
}

// applyOwnership restores the UID and GID of the file at path using os.Lchown.
// Requires the process to be running as root (or to have CAP_CHOWN).
// Returns an error if the chown call fails so the caller can log a warning.
func applyOwnership(path string, uid, gid uint32) error {
	return os.Lchown(path, int(uid), int(gid))
}
