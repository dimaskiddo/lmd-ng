package atp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dimaskiddo/lmd-ng/internal/config"
)

func TestProtectedFiles_ProtectBinary(t *testing.T) {
	cfg := &config.Config{}
	// ATP is always on — no toggles needed
	cfg.Quarantine.Path = t.TempDir()

	p := NewProtector(cfg)
	files := p.protectedFiles()

	exe, err := os.Executable()
	if err != nil {
		t.Skip("cannot get executable path")
	}
	resolved, _ := filepath.EvalSymlinks(exe)

	found := false
	for _, f := range files {
		if f == resolved || f == exe {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("binary not in protected files list: got %v", files)
	}
}

func TestProtectedFiles_ClamAV_Off_ByDefault(t *testing.T) {
	cfg := &config.Config{}
	cfg.Quarantine.Path = t.TempDir()
	cfg.Scanner.ClamAVEnabled = false

	p := NewProtector(cfg)
	files := p.protectedFiles()

	for _, f := range files {
		if filepath.Ext(f) == ".cvd" {
			t.Errorf("ClamAV DBs should not be protected when clamav_enabled=false, got: %s", f)
		}
	}
}

func TestProtectedFiles_ClamAV_On(t *testing.T) {
	clamDir := t.TempDir()
	os.WriteFile(filepath.Join(clamDir, "main.cvd"), []byte("mock"), 0o644)

	cfg := &config.Config{}
	cfg.Quarantine.Path = t.TempDir()
	cfg.Scanner.ClamAVEnabled = true
	cfg.Scanner.ClamAVDBPath = clamDir

	p := NewProtector(cfg)
	files := p.protectedFiles()

	found := false
	for _, f := range files {
		if filepath.Base(f) == "main.cvd" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ClamAV DBs should be protected when clamav_enabled=true")
	}
}
