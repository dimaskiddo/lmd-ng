package upgrade

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
)

// expectedChecksumEntry parses goreleaser checksums.txt content and returns the
// SHA256 hex string for the given asset filename. Format per line:
//
//	<sha256>  <filename>
//
// Returns "" if the asset is not listed.
func expectedChecksumEntry(checksumsData, assetName string) string {
	scanner := bufio.NewScanner(strings.NewReader(checksumsData))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 && parts[1] == assetName {
			return parts[0]
		}
	}
	return ""
}

// fileSHA256 computes the SHA256 of a file and returns it as a hex string.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("cannot open %s: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, err)
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// verifyFileHash asserts that the file at path hashes to expectedHexSha256.
func verifyFileHash(path, expectedHexSha256 string) error {
	actual, err := fileSHA256(path)
	if err != nil {
		return err
	}
	if actual != expectedHexSha256 {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s",
			path, expectedHexSha256, actual)
	}
	return nil
}
