package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrSymlinkDepthExceeded is returned when a symlink chain exceeds the
// configured maximum recursion depth.
var ErrSymlinkDepthExceeded = errors.New("symlink depth exceeded")

// ResolveSymlink follows a chain of symbolic links, returning the path
// of the first non-symlink target found. It iterates up to maxDepth
// levels (or a hard OS cap of 255 if maxDepth is 0).
//
// Relative symlink targets are joined against the parent directory of
// the link, following standard OS semantics.
func ResolveSymlink(path string, maxDepth int) (string, error) {
	const hardLimit = 255

	if maxDepth <= 0 || maxDepth > hardLimit {
		maxDepth = hardLimit
	}

	current := path

	for depth := 0; depth < maxDepth; depth++ {
		info, err := os.Lstat(current)
		if err != nil {
			return "", fmt.Errorf("symlink resolve lstat %s: %w", current, err)
		}

		if info.Mode()&os.ModeSymlink == 0 {
			// Reached a real file/directory — done.
			return current, nil
		}

		target, err := os.Readlink(current)
		if err != nil {
			return "", fmt.Errorf("symlink resolve readlink %s: %w", current, err)
		}

		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(current), target)
		}

		current = target
	}

	// Exhausted maxDepth — check if final target is still a symlink.
	info, err := os.Lstat(current)
	if err != nil {
		return "", fmt.Errorf("symlink resolve lstat %s: %w", current, err)
	}

	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: exceeded %d levels at %s", ErrSymlinkDepthExceeded, maxDepth, path)
	}

	return current, nil
}
