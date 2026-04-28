//go:build !windows

package scanner

import (
	"fmt"
	"os"
	"os/user"
	"syscall"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// applyOwnerFilters checks if the given file should be skipped based on
// owner/group configuration (ignore_root, ignore_users, ignore_groups).
// Returns true if the file should be skipped.
// This implementation uses syscall.Stat_t, which is only available on Unix-like systems.
func applyOwnerFilters(path string, info os.FileInfo, cfg *config.Config) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}

	uid := stat.Uid
	gid := stat.Gid

	// Ignore root if configured (UID 0 is root)
	if cfg.Scanner.IgnoreRoot && uid == 0 {
		log.Debug("Skipping file owned by root", "path", path)
		return true
	}

	// Ignore specific users
	if len(cfg.Scanner.IgnoreUsers) > 0 {
		if u, err := user.LookupId(fmt.Sprint(uid)); err == nil {
			for _, ignoredUser := range cfg.Scanner.IgnoreUsers {
				if u.Username == ignoredUser {
					log.Debug("Skipping file due to ignore_users", "path", path, "user", ignoredUser)
					return true
				}
			}
		}
	}

	// Ignore specific groups
	if len(cfg.Scanner.IgnoreGroups) > 0 {
		if g, err := user.LookupGroupId(fmt.Sprint(gid)); err == nil {
			for _, ignoredGroup := range cfg.Scanner.IgnoreGroups {
				if g.Name == ignoredGroup {
					log.Debug("Skipping file due to ignore_groups", "path", path, "group", ignoredGroup)
					return true
				}
			}
		}
	}

	return false
}
