package upgrade

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestExpectedChecksumEntry_Found(t *testing.T) {
	data := "abc123def456  lmd-ng_0.3.0_linux_64-bit.zip\ndef789  lmd-ng_0.3.0_macos_arm-64-bit.zip\n"
	got := expectedChecksumEntry(data, "lmd-ng_0.3.0_linux_64-bit.zip")
	if got != "abc123def456" {
		t.Fatalf("expected abc123def456, got %q", got)
	}
}

func TestExpectedChecksumEntry_NotFound(t *testing.T) {
	data := "abc123  other.zip\n"
	got := expectedChecksumEntry(data, "lmd-ng_0.3.0_linux_64-bit.zip")
	if got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}

func TestFileSHA256_Correct(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.dat")
	content := []byte("hello checksum")
	if err := os.WriteFile(f, content, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := fileSHA256(f)
	if err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf("%x", sha256.Sum256(content))
	if got != expected {
		t.Fatalf("expected %s, got %s", expected, got)
	}
}

func TestVerifyFileHash_Match(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.dat")
	content := []byte("data")
	if err := os.WriteFile(f, content, 0o644); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(content))
	if err := verifyFileHash(f, hash); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestVerifyFileHash_Mismatch(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "test.dat")
	if err := os.WriteFile(f, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyFileHash(f, "0000000000000000000000000000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected error on mismatch")
	}
}
