package scanner

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
	"github.com/dimaskiddo/lmd-ng/internal/util"
)

// Walker traverses file systems and applies filters.
type Walker struct {
	cfg *config.Config

	parsedMaxFilesize int64
	includeRegex      *regexp.Regexp
	excludeRegex      *regexp.Regexp
	scanIgnore        []string // normalized glob patterns for file exclusion
}

// NewWalker creates a new file system walker with the given configuration.
func NewWalker(cfg *config.Config) (*Walker, error) {
	w := &Walker{
		cfg: cfg,
	}

	// Parse MaxFilesize string
	if cfg.Scanner.MaxFilesize != "0" && cfg.Scanner.MaxFilesize != "" {
		size, err := util.ParseSizeString(cfg.Scanner.MaxFilesize)
		if err != nil {
			return nil, fmt.Errorf("failed to parse scanner.max_filesize: %w", err)
		}

		w.parsedMaxFilesize = size
	}

	// Compile include and exclude regexes
	if cfg.Scanner.IncludeRegex != "" {
		r, err := regexp.Compile(cfg.Scanner.IncludeRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid scanner.include_regex: %w", err)
		}

		w.includeRegex = r
	}

	if cfg.Scanner.ExcludeRegex != "" {
		r, err := regexp.Compile(cfg.Scanner.ExcludeRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid scanner.exclude_regex: %w", err)
		}

		w.excludeRegex = r
	}

	// Normalize scan_ignore_file_patterns: extension shorthand ".ext" → "*.ext"
	w.scanIgnore = normalizeScanIgnorePatterns(cfg.Scanner.ScanIgnoreFilePatterns)

	return w, nil
}

// normalizeScanIgnorePatterns expands extension shorthand patterns into
// full globs. Bare extensions like ".log" become "*.log". Patterns that
// already contain glob characters are passed through unchanged.
func normalizeScanIgnorePatterns(patterns []string) []string {
	if len(patterns) == 0 {
		return nil
	}

	result := make([]string, 0, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// Bare extension: starts with "." and contains no glob chars
		if strings.HasPrefix(p, ".") && !strings.ContainsAny(p, "*?[\\") {
			result = append(result, "*"+p)
		} else {
			result = append(result, p)
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

// Walk traverses the file system from the given root and calls the provided function for each matching file.
// If root is a regular file, it applies filters and calls fn directly for that file.
func (w *Walker) Walk(ctx context.Context, root string, fn func(path string, info os.FileInfo) error) error {
	// Try to evaluate any symlinks in the root path so that if a symlink is passed
	// (either to a file or a directory), we operate on its true target.
	evalRoot, err := filepath.EvalSymlinks(root)
	if err == nil {
		root = evalRoot
	}

	// Check if root is a file (not a directory)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warn("Scan target does not exist", "path", root, "error", err)
			return nil
		}

		return fmt.Errorf("failed to stat scan target %s: %w", root, err)
	}

	// If root is a regular file, apply filters and scan it directly
	if rootInfo.Mode().IsRegular() || rootInfo.Mode()&fs.ModeSymlink != 0 {
		return w.ApplyFilters(ctx, root, rootInfo, fn)
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			// Log permission errors at debug level, others at warn.
			if os.IsPermission(err) {
				log.Debug("Permission denied during file traversal", "path", path, "error", err)
			} else {
				log.Warn("Error during file traversal", "path", path, "error", err)
			}

			return nil // Continue traversal for other files/directories
		}

		info, err := d.Info()
		if err != nil {
			log.Warn("Failed to get file info", "path", path, "error", err)
			return nil
		}

		if d.IsDir() {
			// Check depth for directories
			depth, err := getPathDepth(root, path)
			if err != nil {
				log.Error("Failed to get path depth", "root", root, "path", path, "error", err)
				return nil // Continue on error
			}

			if w.cfg.Scanner.MaxDepth > 0 && depth >= w.cfg.Scanner.MaxDepth {
				log.Debug("Skipping directory due to max depth", "path", path, "depth", depth, "max_depth", w.cfg.Scanner.MaxDepth)
				return filepath.SkipDir // Skip this directory and its children
			}

			// Check if directory is in exclude_dirs
			if util.IsPathExcluded(path, w.cfg.Monitor.ExcludeDirs) {
				log.Debug("Skipping directory due to exclude_dirs", "path", path)
				return filepath.SkipDir
			}

			return nil
		}

		return w.ApplyFilters(ctx, path, info, fn)
	})
}

// getPathDepth calculates the depth of a given path relative to a root path.
// e.g., root=/a, path=/a/b/c -> depth=2
func getPathDepth(root, path string) (int, error) {
	relPath, err := filepath.Rel(root, path)
	if err != nil {
		return 0, fmt.Errorf("failed to get relative path: %w", err)
	}

	if relPath == "." {
		return 0, nil
	}

	// Count path separators
	return strings.Count(relPath, string(filepath.Separator)), nil
}

// ApplyFilters handles scanning a single file target, applying all configured
// filters (filesize, user/group ignore, regex, and symlink resolution) before
// calling the scan callback.
func (w *Walker) ApplyFilters(ctx context.Context, path string, info os.FileInfo, fn func(string, os.FileInfo) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// If it is a symlink, resolve it to get its true type and size
	if info.Mode()&fs.ModeSymlink != 0 {
		resolved, err := util.ResolveSymlink(path, w.cfg.Scanner.MaxSymlinkDepth)
		if err != nil {
			log.Debug("Failed to resolve symlink", "path", path, "error", err)
			return nil
		}
		targetInfo, err := os.Lstat(resolved)
		if err != nil {
			log.Debug("Failed to stat symlink target", "path", path, "resolved", resolved, "error", err)
			return nil
		}
		info = targetInfo
		path = resolved
	}

	// If it's not a regular file, skip it (e.g., devices, sockets, or symlinks to directories)
	if !info.Mode().IsRegular() {
		log.Debug("Skipping non-regular file", "path", path, "mode", info.Mode())
		return nil
	}

	// Apply file size filters
	if info.Size() < w.cfg.Scanner.MinFilesize {
		log.Debug("Skipping file due to min_filesize", "path", path, "size", info.Size(), "min_filesize", w.cfg.Scanner.MinFilesize)
		return nil
	}

	if w.parsedMaxFilesize > 0 && info.Size() > w.parsedMaxFilesize {
		log.Debug("Skipping file due to max_filesize", "path", path, "size", info.Size(), "max_filesize", w.cfg.Scanner.MaxFilesize)
		return nil
	}

	// Apply ignore_root, ignore_user, ignore_group filters (Unix only; no-op on Windows)
	if applyOwnerFilters(path, info, w.cfg) {
		return nil
	}

	// Apply scan_ignore file pattern exclusion (filename-only matching)
	if len(w.scanIgnore) > 0 {
		baseName := filepath.Base(path)
		for _, pattern := range w.scanIgnore {
			if matched, _ := filepath.Match(pattern, baseName); matched {
				log.Debug("Skipping file (scan_ignore)", "path", path, "pattern", pattern)
				return nil
			}
		}
	}

	// Skip orphan inodes and system temp artifacts
	if util.IsOrphanTempFile(path, info) {
		return nil
	}

	// Skip editor/tool lock files (Emacs, GnuPG)
	if util.IsLockFilePath(path) {
		return nil
	}

	// Apply regex filters
	if w.excludeRegex != nil && w.excludeRegex.MatchString(path) {
		log.Debug("Skipping file due to exclude_regex", "path", path, "regex", w.cfg.Scanner.ExcludeRegex)
		return nil
	}

	if w.includeRegex != nil && !w.includeRegex.MatchString(path) {
		log.Debug("Skipping file due to include_regex mismatch", "path", path, "regex", w.cfg.Scanner.IncludeRegex)
		return nil
	}

	return fn(path, info)
}
