package updater

import (
	"crypto/md5"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dimaskiddo/lmd-ng/internal/config"
)

func TestParseChecksumLine_Found(t *testing.T) {
	data := "2e2ae2696afc3093cae2f5b3f3066a05a0a6f8e9d43b9f90a4c0c7f3e25a45f6  maldet-sigpack.tgz\n"
	hex, ok := parseChecksumLine(data, "maldet-sigpack.tgz")
	if !ok || len(hex) != 64 {
		t.Fatalf("expected 64-char hex, got ok=%v hex=%q", ok, hex)
	}
}

func TestParseChecksumLine_NotFound(t *testing.T) {
	data := "abc  other.tgz\n"
	if _, ok := parseChecksumLine(data, "maldet-sigpack.tgz"); ok {
		t.Fatal("expected not found")
	}
}

func TestParseChecksumLine_UpperNormalized(t *testing.T) {
	data := "ABCDEF  maldet-sigpack.tgz\n"
	hex, ok := parseChecksumLine(data, "maldet-sigpack.tgz")
	if !ok || hex != "abcdef" {
		t.Fatalf("expected lowercased hex, got %q", hex)
	}
}

func TestComputeFileDigest_SHA256AndMD5(t *testing.T) {
	content := []byte("signature pack bytes")
	tmp := t.TempDir()
	path := filepath.Join(tmp, "test.tgz")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	sha, err := computeFileDigest(path, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(sha) != 64 {
		t.Fatalf("expected 64-char sha256, got %d", len(sha))
	}
	if sha != fmt.Sprintf("%x", sha256.Sum256(content)) {
		t.Fatal("sha256 mismatch")
	}

	md, err := computeFileDigest(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(md) != 32 {
		t.Fatalf("expected 32-char md5, got %d", len(md))
	}
	if md != fmt.Sprintf("%x", md5.Sum(content)) {
		t.Fatal("md5 mismatch")
	}
}

func TestComputeFileDigest_BadLength(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "t")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := computeFileDigest(path, 17); err == nil {
		t.Fatal("expected error for unsupported digest length")
	}
}

// newTestUpdater starts an httptest server serving the sigpack plus its
// checksum sidecars, and returns an Updater pointed at it.
func newTestUpdater(t *testing.T, packContent []byte) (*Updater, *httptest.Server) {
	t.Helper()
	shaSidecar := fmt.Sprintf("%x  sigpack.tgz\n", sha256.Sum256(packContent))
	md5Sidecar := fmt.Sprintf("%x  sigpack.tgz\n", md5.Sum(packContent))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sigpack.tgz":
			_, _ = w.Write(packContent)
		case "/sigpack.tgz.sha256":
			_, _ = w.Write([]byte(shaSidecar))
		case "/sigpack.tgz.md5":
			_, _ = w.Write([]byte(md5Sidecar))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{}
	cfg.Updater.SignaturePackURL = srv.URL + "/sigpack.tgz"
	cfg.Updater.SignatureChecksumSuffix = ".sha256"
	cfg.Updater.SignatureChecksumURL = ""
	cfg.Updater.RemoteURITimeout = "5s"
	return NewUpdater(cfg), srv
}

func TestFetchSigpackChecksum_SHA256Sibling(t *testing.T) {
	content := []byte("test pack bytes")
	u, _ := newTestUpdater(t, content)

	u2 := &Updater{cfg: u.cfg, httpClient: u.httpClient}
	_, hex, err := u2.fetchSigpackChecksum(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(hex) != 64 {
		t.Fatalf("expected 64-char sha256 from sibling, got %d", len(hex))
	}
}

func TestFetchSigpackChecksum_MD5Fallback(t *testing.T) {
	content := []byte("test pack bytes")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// .sha256 404s; only .md5 is served.
		switch r.URL.Path {
		case "/sigpack.tgz.sha256":
			http.NotFound(w, r)
		case "/sigpack.tgz.md5":
			_, _ = w.Write([]byte(fmt.Sprintf("%x  sigpack.tgz\n", md5.Sum(content))))
		default:
			if r.URL.Path == "/sigpack.tgz" {
				_, _ = w.Write(content)
				return
			}
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{}
	cfg.Updater.SignaturePackURL = srv.URL + "/sigpack.tgz"
	cfg.Updater.SignatureChecksumSuffix = ".sha256"
	cfg.Updater.RemoteURITimeout = "5s"
	u := NewUpdater(cfg)

	_, hex, err := u.fetchSigpackChecksum(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(hex) != 32 {
		t.Fatalf("expected 32-char md5 fallback, got %d (%q)", len(hex), hex)
	}
}

func TestVerifySignaturePackChecksum_PassesAndFails(t *testing.T) {
	content := []byte("the real signatures")
	u, _ := newTestUpdater(t, content)

	// Temp pack with exact content → passes.
	good := filepath.Join(t.TempDir(), "pack.tgz")
	if err := os.WriteFile(good, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := u.verifySignaturePackChecksum(t.Context(), good); err != nil {
		t.Fatalf("expected pass, got: %v", err)
	}

	// Temp pack with different content → fails.
	bad := filepath.Join(t.TempDir(), "pack.tgz")
	if err := os.WriteFile(bad, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := u.verifySignaturePackChecksum(t.Context(), bad); err == nil {
		t.Fatal("expected checksum mismatch error for tampered pack")
	} else {
		_ = strings.Contains(err.Error(), "mismatch")
	}
}
