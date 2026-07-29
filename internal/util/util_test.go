package util

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsOrphanTempFile_NlinkZero(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Nlink check not applicable on Windows")
	}

	// Create file, unlink it while fd is still open → Nlink drops to 0
	dir := t.TempDir()
	target := filepath.Join(dir, "orphantest")
	if err := os.WriteFile(target, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	f, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Remove directory entry — Nlink goes to 0 but inode survives via fd
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	// Stat the open fd to get inode info with Nlink=0
	info, err := os.Stat(f.Name()) // /proc/self/fd/N on Linux
	if err != nil {
		t.Skip("cannot stat fd path on this platform")
	}

	// Any path works — Nlink=0 check fires regardless of path
	if !IsOrphanTempFile("/some/path", info) {
		t.Error("expected Nlink=0 file to be detected as orphan temp")
	}
}

func TestIsOrphanTempFile_HashInTmp(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires /tmp on Unix")
	}

	// Create a real file in /tmp with # prefix — will have Nlink=1
	tmpFile := filepath.Join(os.TempDir(), "#test-orphan-sentinel")
	os.Remove(tmpFile) // clean leftover from prior runs
	if err := os.WriteFile(tmpFile, []byte("x"), 0644); err != nil {
		t.Skip("cannot write to system /tmp")
	}
	defer os.Remove(tmpFile)

	info, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	if !IsOrphanTempFile(tmpFile, info) {
		t.Errorf("expected # file in %s to be detected as temp artifact", os.TempDir())
	}
}

func TestIsOrphanTempFile_NoHashPrefix(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "legit.txt")
	os.WriteFile(regular, []byte("x"), 0644)
	info, _ := os.Stat(regular)

	if IsOrphanTempFile(regular, info) {
		t.Error("expected regular file without # prefix to NOT be orphan temp")
	}
}

func TestIsOrphanTempFile_HashOutsideTmp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows path logic differs")
	}

	// # file outside /tmp — must NOT be excluded (evasion guard)
	// Use cwd as parent — definitely not /tmp or /var/tmp
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	evasionDir := filepath.Join(cwd, "test-orphan-evasion")
	os.MkdirAll(evasionDir, 0o755)
	defer os.RemoveAll(evasionDir)

	hashFile := filepath.Join(evasionDir, "#malware")
	if err := os.WriteFile(hashFile, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(hashFile)

	info, err := os.Stat(hashFile)
	if err != nil {
		t.Fatal(err)
	}

	if IsOrphanTempFile(hashFile, info) {
		t.Error("expected # file outside /tmp to NOT be orphan temp (evasion guard)")
	}
}

func TestIsOrphanTempPath_HashInTmp(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires /tmp on Unix")
	}

	tmpFile := filepath.Join(os.TempDir(), "#test-orphanpath-sentinel")
	os.Remove(tmpFile)
	if err := os.WriteFile(tmpFile, []byte("x"), 0644); err != nil {
		t.Skip("cannot write to system /tmp")
	}
	defer os.Remove(tmpFile)

	if !IsOrphanTempPath(tmpFile) {
		t.Errorf("expected # file in %s to be detected by path check", os.TempDir())
	}
}

func TestIsOrphanTempPath_NoHashPrefix(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "legit.txt")
	if IsOrphanTempPath(regular) {
		t.Error("regular file without # prefix should not match")
	}
}

func TestIsOrphanTempPath_HashOutsideTmp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows path logic differs")
	}

	// Use cwd as parent — definitely not /tmp or /var/tmp
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(cwd, "#outside")
	if IsOrphanTempPath(outside) {
		t.Error("# file outside /tmp should not match")
	}
}
