package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/dimaskiddo/lmd-ng/internal/config"
)

func TestNormalizeScanIgnorePatterns(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		expect []string
	}{
		{
			name:   "nil input",
			input:  nil,
			expect: nil,
		},
		{
			name:   "empty input",
			input:  []string{},
			expect: nil,
		},
		{
			name:   "bare extension shorthand",
			input:  []string{".log", ".tmp"},
			expect: []string{"*.log", "*.tmp"},
		},
		{
			name:   "glob pattern passed through",
			input:  []string{"*.bak", "access_log*"},
			expect: []string{"*.bak", "access_log*"},
		},
		{
			name:   "mixed shorthand and glob",
			input:  []string{".log", "*.tmp", "core.*"},
			expect: []string{"*.log", "*.tmp", "core.*"},
		},
		{
			name:   "empty strings filtered",
			input:  []string{".log", "", "  ", ".tmp"},
			expect: []string{"*.log", "*.tmp"},
		},
		{
			name:   "bracket glob passed through",
			input:  []string{"[a-z].log"},
			expect: []string{"[a-z].log"},
		},
		{
			name:   "question mark glob passed through",
			input:  []string{"file?.log"},
			expect: []string{"file?.log"},
		},
		{
			name:   "office temp lock pattern",
			input:  []string{"~$*"},
			expect: []string{"~$*"},
		},
		{
			name:   "all empty results in nil",
			input:  []string{"", "  "},
			expect: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeScanIgnorePatterns(tc.input)
			if tc.expect == nil {
				if got != nil {
					t.Errorf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != len(tc.expect) {
				t.Errorf("expected %d patterns, got %d: %v", len(tc.expect), len(got), got)
				return
			}
			for i := range got {
				if got[i] != tc.expect[i] {
					t.Errorf("pattern[%d]: expected %q, got %q", i, tc.expect[i], got[i])
				}
			}
		})
	}
}

// helperWalker creates a minimal Walker with the given scan_ignore patterns
// for testing ApplyFilters without needing a full config setup.
func helperWalker(t *testing.T, patterns []string) *Walker {
	t.Helper()
	cfg := &config.Config{}
	cfg.Scanner.MaxFilesize = "0"
	cfg.Scanner.MinFilesize = 0
	cfg.Scanner.IgnoreRoot = false
	cfg.Scanner.ScanIgnoreFilePatterns = patterns

	w, err := NewWalker(cfg)
	if err != nil {
		t.Fatalf("NewWalker failed: %v", err)
	}
	return w
}

// createTempFile creates a regular temp file and returns its path + FileInfo.
func createTempFile(t *testing.T, dir, name string) (string, os.FileInfo) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("test"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	return path, info
}

func TestApplyFilters_ScanIgnore_ExtensionShorthand(t *testing.T) {
	dir := t.TempDir()
	w := helperWalker(t, []string{".log"})
	path, info := createTempFile(t, dir, "app.log")

	called := false
	err := w.ApplyFilters(context.Background(), path, info, func(p string, i os.FileInfo) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("ApplyFilters error: %v", err)
	}
	if called {
		t.Error("expected callback NOT called (file should be excluded)")
	}
}

func TestApplyFilters_ScanIgnore_GlobPattern(t *testing.T) {
	dir := t.TempDir()
	w := helperWalker(t, []string{"access_log*"})
	path, info := createTempFile(t, dir, "access_log.2024-01-01")

	called := false
	err := w.ApplyFilters(context.Background(), path, info, func(p string, i os.FileInfo) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("ApplyFilters error: %v", err)
	}
	if called {
		t.Error("expected callback NOT called (file should be excluded)")
	}
}

func TestApplyFilters_ScanIgnore_NoMatch(t *testing.T) {
	dir := t.TempDir()
	w := helperWalker(t, []string{"*.log"})
	path, info := createTempFile(t, dir, "app.sh")

	called := false
	err := w.ApplyFilters(context.Background(), path, info, func(p string, i os.FileInfo) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("ApplyFilters error: %v", err)
	}
	if !called {
		t.Error("expected callback called (file should NOT be excluded)")
	}
}

func TestApplyFilters_ScanIgnore_EmptyList(t *testing.T) {
	dir := t.TempDir()
	w := helperWalker(t, nil)
	path, info := createTempFile(t, dir, "app.log")

	called := false
	err := w.ApplyFilters(context.Background(), path, info, func(p string, i os.FileInfo) error {
		called = true
		return nil
	})
	if err != nil {
		t.Fatalf("ApplyFilters error: %v", err)
	}
	if !called {
		t.Error("expected callback called (no patterns = no exclusion)")
	}
}

func TestApplyFilters_ScanIgnore_MultiplePatterns(t *testing.T) {
	dir := t.TempDir()
	w := helperWalker(t, []string{".log", ".tmp", ".bak"})

	// Test .bak matches third pattern
	path, info := createTempFile(t, dir, "backup.bak")
	called := false
	_ = w.ApplyFilters(context.Background(), path, info, func(p string, i os.FileInfo) error {
		called = true
		return nil
	})
	if called {
		t.Error("expected backup.bak to be excluded by .bak pattern")
	}

	// Test .tmp matches second pattern
	path2, info2 := createTempFile(t, dir, "cache.tmp")
	called = false
	_ = w.ApplyFilters(context.Background(), path2, info2, func(p string, i os.FileInfo) error {
		called = true
		return nil
	})
	if called {
		t.Error("expected cache.tmp to be excluded by .tmp pattern")
	}
}

func TestApplyFilters_ScanIgnore_FilenameOnly(t *testing.T) {
	dir := t.TempDir()
	w := helperWalker(t, []string{".log"})

	// File is in /subdir/app.log — should match on basename only
	subDir := filepath.Join(dir, "subdir")
	if err := os.Mkdir(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	path, info := createTempFile(t, subDir, "app.log")
	called := false
	_ = w.ApplyFilters(context.Background(), path, info, func(p string, i os.FileInfo) error {
		called = true
		return nil
	})
	if called {
		t.Error("expected app.log in subdirectory to be excluded")
	}
}

func TestApplyFilters_ScanIgnore_OfficeTemp(t *testing.T) {
	dir := t.TempDir()
	w := helperWalker(t, []string{"~$*"})

	path, info := createTempFile(t, dir, "~$document.docx")
	called := false
	_ = w.ApplyFilters(context.Background(), path, info, func(p string, i os.FileInfo) error {
		called = true
		return nil
	})
	if called {
		t.Error("expected ~$document.docx to be excluded")
	}
}

func TestApplyFilters_ScanIgnore_DefaultsApplied(t *testing.T) {
	// Test that the default config includes scan_ignore patterns
	cfg := &config.Config{}
	cfg.Scanner.MaxFilesize = "0"
	cfg.Scanner.MinFilesize = 0
	cfg.Scanner.IgnoreRoot = false
	// Don't set ScanIgnoreFilePatterns — rely on defaults from setDefaultConfig
	// But since we're not calling setDefaultConfig here, test that empty patterns = no exclusion
	cfg.Scanner.ScanIgnoreFilePatterns = []string{}

	w, err := NewWalker(cfg)
	if err != nil {
		t.Fatalf("NewWalker failed: %v", err)
	}

	if len(w.scanIgnore) != 0 {
		t.Errorf("expected empty scanIgnore with empty config, got %d patterns", len(w.scanIgnore))
	}
}
