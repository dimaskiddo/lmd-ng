package dbs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
)

func TestCleanOrphanTempFiles(t *testing.T) {
	// Setup: create a temp base path with leftover lmd-scan-* files
	baseDir := t.TempDir()
	tmpDir := filepath.Join(baseDir, "tmp")
	os.MkdirAll(tmpDir, 0o700)

	// Create orphan files
	orphans := []string{"lmd-scan-12345", "lmd-scan-abcde", "lmd-scan-99999"}
	for _, name := range orphans {
		os.WriteFile(filepath.Join(tmpDir, name), []byte("orphan"), 0o600)
	}

	// Create a non-orphan file (should NOT be deleted)
	os.WriteFile(filepath.Join(tmpDir, "legitimate.dat"), []byte("data"), 0o600)

	cfg := &config.Config{}
	cfg.App.BasePath = baseDir

	s := &Server{cfg: cfg}
	s.cleanOrphanTempFiles()

	// Verify orphans removed
	entries, _ := os.ReadDir(tmpDir)
	for _, entry := range entries {
		if entry.Name() == "legitimate.dat" {
			continue
		}
		t.Errorf("expected orphan %s to be removed, but it still exists", entry.Name())
	}
}

func TestCleanOrphanTempFiles_NoTmpDir(t *testing.T) {
	// Should not panic when tmp directory doesn't exist
	cfg := &config.Config{}
	cfg.App.BasePath = t.TempDir()

	s := &Server{cfg: cfg}
	s.cleanOrphanTempFiles() // no error expected
}

func TestRemoveStaleTempFiles(t *testing.T) {
	baseDir := t.TempDir()
	tmpDir := filepath.Join(baseDir, "tmp")
	os.MkdirAll(tmpDir, 0o700)

	// Create a stale file (old timestamp)
	stalePath := filepath.Join(tmpDir, "lmd-scan-old")
	os.WriteFile(stalePath, []byte("stale"), 0o600)
	os.Chtimes(stalePath, time.Now().Add(-10*time.Minute), time.Now().Add(-10*time.Minute))

	// Create a fresh file (recent timestamp)
	freshPath := filepath.Join(tmpDir, "lmd-scan-new")
	os.WriteFile(freshPath, []byte("fresh"), 0o600)

	cfg := &config.Config{}
	cfg.App.BasePath = baseDir

	s := &Server{cfg: cfg}
	s.removeStaleTempFiles(5 * time.Minute)

	// Stale should be gone
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Error("expected stale file to be removed")
	}

	// Fresh should remain
	if _, err := os.Stat(freshPath); err != nil {
		t.Error("expected fresh file to remain")
	}
}

func TestRemoveStaleTempFiles_NonScanFilesUntouched(t *testing.T) {
	baseDir := t.TempDir()
	tmpDir := filepath.Join(baseDir, "tmp")
	os.MkdirAll(tmpDir, 0o700)

	// Create an old file that is NOT lmd-scan-* — must not be deleted
	otherPath := filepath.Join(tmpDir, "lmd-upgrade-old.zip")
	os.WriteFile(otherPath, []byte("other"), 0o600)
	os.Chtimes(otherPath, time.Now().Add(-10*time.Minute), time.Now().Add(-10*time.Minute))

	cfg := &config.Config{}
	cfg.App.BasePath = baseDir

	s := &Server{cfg: cfg}
	s.removeStaleTempFiles(5 * time.Minute)

	if _, err := os.Stat(otherPath); err != nil {
		t.Error("expected non-scan file to remain untouched")
	}
}
