package quarantine

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

const (
	filePerm  = 0o000 // Read/write/execute denied for all
	chunkSize = 4096  // 4KB chunk size for file operations in stream encryption/decryption
)

// Metadata stores information about a quarantined file.
type Metadata struct {
	OriginalPath   string `json:"original_path"`
	QuarantinePath string `json:"quarantine_path"`
	DetectionInfo  string `json:"detection_info"`
	EncryptionKey  []byte `json:"encryption_key,omitempty"` // Encrypted file-specific key
	Nonce          []byte `json:"nonce,omitempty"`          // Nonce used for GCM encryption
}

// ListEntry is a summary of a single quarantined file returned by List.
type ListEntry struct {
	// ID is the full 32-character hex UUID embedded in the quarantine filename.
	ID string
	// ShortID is the first 8 characters of ID, used for convenient CLI references.
	ShortID string
	OriginalPath   string
	QuarantinePath string
	DetectionInfo  string
	Encrypted      bool
}

// Manager defines the interface for quarantine operations.
type Manager interface {
	Quarantine(ctx context.Context, filePath string, detectionInfo string) (string, error)
	Restore(ctx context.Context, quarantinePath string) (string, error)
	List(ctx context.Context) ([]ListEntry, error)
	ResolveByID(id string) (string, error)
}

// QuarantineManager implements the Manager interface.
type QuarantineManager struct {
	cfg *config.QuarantineConfig
}

// NewQuarantineManager creates a new QuarantineManager.
func NewQuarantineManager(cfg *config.QuarantineConfig) *QuarantineManager {
	return &QuarantineManager{
		cfg: cfg,
	}
}

// Quarantine moves a file to quarantine, sets permissions, and optionally encrypts it.
// Returns the path to the quarantined file and an error if any.
func (qm *QuarantineManager) Quarantine(ctx context.Context, filePath string, detectionInfo string) (string, error) {
	// Ensure quarantine directory exists
	if err := os.MkdirAll(qm.cfg.Path, 0o700); err != nil {
		return "", fmt.Errorf("failed to create quarantine directory %s: %w", qm.cfg.Path, err)
	}

	// Generate a unique filename for the quarantined file
	fileName := filepath.Base(filePath)

	uniqueIDBytes := make([]byte, 16)
	if _, err := rand.Read(uniqueIDBytes); err != nil {
		return "", fmt.Errorf("failed to generate unique quarantine ID: %w", err)
	}

	uniqueID := hex.EncodeToString(uniqueIDBytes)
	quarantineFileName := fmt.Sprintf("%s.%s.quarantined", fileName, uniqueID)
	quarantinePath := filepath.Join(qm.cfg.Path, quarantineFileName)

	// Prepare metadata
	metadata := Metadata{
		OriginalPath:  filePath,
		DetectionInfo: detectionInfo,
	}

	finalQuarantinePath := quarantinePath

	if qm.cfg.EnableEncryption {
		if qm.cfg.EncryptionKey == "" {
			return "", fmt.Errorf("quarantine encryption is enabled but encryption_key is empty in config")
		}

		masterKey := deriveMasterKey(qm.cfg.EncryptionKey)

		// Generate a new random file key for this file
		fileKey := make([]byte, 32)
		if _, err := rand.Read(fileKey); err != nil {
			return "", fmt.Errorf("failed to generate file encryption key: %w", err)
		}

		// Encrypt the file content
		encryptedFilePath, nonce, err := qm.encryptFile(filePath, fileKey)
		if err != nil {
			// If encryption fails, try to move the original file to quarantine unencrypted
			log.Error("Failed to encrypt file, attempting to quarantine unencrypted", "file", filePath, "error", err)

			if moveErr := moveFile(filePath, quarantinePath); moveErr != nil {
				return "", fmt.Errorf("failed to move original file to quarantine after encryption failure: %w", moveErr)
			}

			metadata.QuarantinePath = quarantinePath
		} else {
			// Move the encrypted file to the final quarantine path
			if err := moveFile(encryptedFilePath, quarantinePath); err != nil {
				return "", fmt.Errorf("failed to move encrypted file to quarantine %s: %w", quarantinePath, err)
			}

			// Encrypt the file key with the master key
			encryptedFileKey, err := qm.encryptKeyWithMaster(fileKey, masterKey)
			if err != nil {
				// This is a critical error, as we can't decrypt later. Abort.
				// Attempt to delete quarantined file to prevent unrecoverable state.
				_ = os.Remove(quarantinePath)
				return "", fmt.Errorf("failed to encrypt file key with master key: %w", err)
			}

			metadata.EncryptionKey = encryptedFileKey
			metadata.Nonce = nonce
			metadata.QuarantinePath = quarantinePath

			finalQuarantinePath = quarantinePath
		}
	} else {
		// If encryption is not enabled, just move the original file
		if err := moveFile(filePath, quarantinePath); err != nil {
			return "", fmt.Errorf("failed to move file %s to quarantine %s: %w", filePath, quarantinePath, err)
		}

		metadata.QuarantinePath = quarantinePath
	}

	// Set restrictive permissions on the final quarantined file
	if err := os.Chmod(finalQuarantinePath, filePerm); err != nil {
		log.Warn("Failed to set restrictive permissions on quarantined file", "file", finalQuarantinePath, "error", err)
	}

	// Save metadata to a separate JSON file
	metadataFilePath := finalQuarantinePath + ".metadata.json"

	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		log.Error("Failed to marshal quarantine metadata", "error", err)

		// Attempt to remove quarantined file to prevent incomplete state
		_ = os.Remove(finalQuarantinePath)

		return "", fmt.Errorf("failed to marshal quarantine metadata: %w", err)
	}

	if err := os.WriteFile(metadataFilePath, metadataBytes, 0o600); err != nil {
		log.Error("Failed to write quarantine metadata file", "file", metadataFilePath, "error", err)

		// Attempt to remove quarantined file to prevent incomplete state
		_ = os.Remove(finalQuarantinePath)
		_ = os.Remove(metadataFilePath)

		return "", fmt.Errorf("failed to write quarantine metadata file %s: %w", metadataFilePath, err)
	}

	log.Info("File quarantined", "original_path", filePath, "quarantine_path", finalQuarantinePath, "detection_info", detectionInfo, "encrypted", qm.cfg.EnableEncryption)

	return finalQuarantinePath, nil
}

// Restore moves a quarantined file back to its original path and optionally decrypts it.
// Returns the original path and an error if any.
func (qm *QuarantineManager) Restore(ctx context.Context, quarantinePath string) (string, error) {
	// Construct metadata file path
	metadataFilePath := quarantinePath + ".metadata.json"

	// Load metadata
	metadataBytes, err := os.ReadFile(metadataFilePath)

	// If metadata file not found, we can't restore
	if os.IsNotExist(err) {
		return "", fmt.Errorf("quarantine metadata file not found for %s: %w", quarantinePath, err)
	}

	if err != nil {
		return "", fmt.Errorf("failed to read quarantine metadata file %s: %w", metadataFilePath, err)
	}

	var metadata Metadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return "", fmt.Errorf("failed to unmarshal quarantine metadata from %s: %w", metadataFilePath, err)
	}

	// The quarantined file was locked to 0o000 permissions at quarantine time.
	// Temporarily grant owner-read so we can open it for decryption or direct move.
	// If anything goes wrong after this point we re-lock the file before returning.
	if err := os.Chmod(quarantinePath, 0o400); err != nil {
		return "", fmt.Errorf("failed to grant read permission on quarantined file %s before restore: %w", quarantinePath, err)
	}

	// lockDown is a best-effort cleanup called on any error after the chmod above.
	lockDown := func() {
		if chmodErr := os.Chmod(quarantinePath, filePerm); chmodErr != nil {
			log.Warn("Failed to re-lock quarantined file after restore error", "file", quarantinePath, "error", chmodErr)
		}
	}

	// The path to the file that will be restored (could be encrypted or not)
	fileToRestorePath := quarantinePath

	if qm.cfg.EnableEncryption && len(metadata.EncryptionKey) > 0 && len(metadata.Nonce) > 0 {
		if qm.cfg.EncryptionKey == "" {
			lockDown()
			return "", fmt.Errorf("quarantine encryption is enabled but encryption_key is empty in config")
		}

		masterKey := deriveMasterKey(qm.cfg.EncryptionKey)

		// Decrypt the file key with the master key
		fileKey, err := qm.decryptKeyWithMaster(metadata.EncryptionKey, masterKey)
		if err != nil {
			lockDown()
			return "", fmt.Errorf("failed to decrypt file encryption key: %w", err)
		}

		// Decrypt the file content. The encrypted file is at `quarantinePath`.
		// decryptFile opens the file with the read permission we just granted and writes
		// the plaintext to a temporary .dec.tmp file alongside the quarantined file.
		decryptedFilePath, err := qm.decryptFile(quarantinePath, fileKey, metadata.Nonce)
		if err != nil {
			lockDown()
			return "", fmt.Errorf("failed to decrypt quarantined file %s: %w", quarantinePath, err)
		}

		fileToRestorePath = decryptedFilePath
	}

	// Restore default permissions on the file that is about to move back.
	// A more robust solution would store original permissions in metadata.
	if err := os.Chmod(fileToRestorePath, 0o644); err != nil {
		log.Warn("Failed to restore default permissions on restored file", "file", fileToRestorePath, "error", err)
	}

	// Move the file back to its original path (handles cross-device moves)
	if err := moveFile(fileToRestorePath, metadata.OriginalPath); err != nil {
		lockDown()
		return "", fmt.Errorf("failed to move file %s to original path %s: %w", fileToRestorePath, metadata.OriginalPath, err)
	}

	log.Info("File restored", "quarantine_path", quarantinePath, "original_path", metadata.OriginalPath)

	// Clean up quarantined file and metadata file.
	// The encrypted source was already removed inside decryptFile; this handles the
	// non-encrypted case (or any leftover) and always removes the metadata sidecar.
	if err := os.Remove(quarantinePath); err != nil && !os.IsNotExist(err) {
		log.Warn("Failed to remove quarantined file after restoration", "file", quarantinePath, "error", err)
	}

	if err := os.Remove(metadataFilePath); err != nil && !os.IsNotExist(err) {
		log.Warn("Failed to remove metadata file after restoration", "file", metadataFilePath, "error", err)
	}

	return metadata.OriginalPath, nil
}

// List returns a summary of all quarantined files by scanning the quarantine directory
// for *.metadata.json sidecar files. Each entry includes a short, human-readable ID
// (first 8 characters of the UUID) that can be passed to ResolveByID for restore operations.
func (qm *QuarantineManager) List(ctx context.Context) ([]ListEntry, error) {
	entries, err := os.ReadDir(qm.cfg.Path)
	if err != nil {
		if os.IsNotExist(err) {
			// Quarantine directory not yet created — return empty list gracefully.
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read quarantine directory %s: %w", qm.cfg.Path, err)
	}

	var list []ListEntry
	for _, de := range entries {
		select {
		case <-ctx.Done():
			return list, ctx.Err()
		default:
		}

		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".quarantined.metadata.json") {
			continue
		}

		metadataPath := filepath.Join(qm.cfg.Path, name)

		data, err := os.ReadFile(metadataPath)
		if err != nil {
			log.Warn("Failed to read quarantine metadata file, skipping", "file", metadataPath, "error", err)
			continue
		}

		var meta Metadata
		if err := json.Unmarshal(data, &meta); err != nil {
			log.Warn("Failed to parse quarantine metadata file, skipping", "file", metadataPath, "error", err)
			continue
		}

		// Extract the UUID from the metadata filename:
		// Format: <original_name>.<uuid>.quarantined.metadata.json
		// We strip the suffix and then take the last dot-delimited segment as the ID.
		baseName := strings.TrimSuffix(name, ".quarantined.metadata.json")
		id := ""
		if idx := strings.LastIndex(baseName, "."); idx >= 0 {
			id = baseName[idx+1:]
		}

		shortID := id
		if len(id) >= 8 {
			shortID = id[:8]
		}

		encrypted := len(meta.EncryptionKey) > 0 && len(meta.Nonce) > 0

		list = append(list, ListEntry{
			ID:             id,
			ShortID:        shortID,
			OriginalPath:   meta.OriginalPath,
			QuarantinePath: meta.QuarantinePath,
			DetectionInfo:  meta.DetectionInfo,
			Encrypted:      encrypted,
		})
	}

	return list, nil
}

// ResolveByID resolves a quarantine path from a user-supplied identifier which may be:
//   - An absolute path to the quarantined file (returned as-is after existence check).
//   - A full 32-character hex ID matching the UUID in the quarantine filename.
//   - A short ID (prefix of the full ID, minimum 4 characters) that uniquely matches
//     exactly one quarantine entry.
//
// Returns the absolute quarantine path and an error if the ID is ambiguous, not found,
// or too short.
func (qm *QuarantineManager) ResolveByID(id string) (string, error) {
	// If the caller provided an absolute path that exists, use it directly.
	if filepath.IsAbs(id) {
		if _, err := os.Stat(id); err == nil {
			return id, nil
		}
	}

	if len(id) < 4 {
		return "", fmt.Errorf("ID %q is too short; provide at least 4 characters of the quarantine ID", id)
	}

	entries, err := os.ReadDir(qm.cfg.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("quarantine directory %s does not exist", qm.cfg.Path)
		}
		return "", fmt.Errorf("failed to read quarantine directory: %w", err)
	}

	var matches []string
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".quarantined") {
			continue
		}

		// Extract UUID from filename: <original_name>.<uuid>.quarantined
		baseName := strings.TrimSuffix(name, ".quarantined")
		entryID := ""
		if idx := strings.LastIndex(baseName, "."); idx >= 0 {
			entryID = baseName[idx+1:]
		}

		if strings.HasPrefix(entryID, id) {
			matches = append(matches, filepath.Join(qm.cfg.Path, name))
		}
	}

	switch len(matches) {
	case 0:
		return "", fmt.Errorf("no quarantined file found matching ID %q", id)
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous ID %q matches %d quarantine entries; use more characters", id, len(matches))
	}
}

// encryptFile encrypts a file using AES256-GCM and returns the path to the encrypted temporary file, the nonce, and an error.
// The original file is removed after successful encryption.
func (qm *QuarantineManager) encryptFile(filePath string, key []byte) (string, []byte, error) {
	plaintextFile, err := os.Open(filePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open plaintext file %s: %w", filePath, err)
	}
	defer plaintextFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Create a temporary file for the ciphertext
	encryptedTempFilePath := filePath + ".enc.tmp"

	ciphertextFile, err := os.Create(encryptedTempFilePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create ciphertext file %s: %w", encryptedTempFilePath, err)
	}
	defer ciphertextFile.Close()

	// Stream encryption
	buffer := make([]byte, chunkSize)
	for {
		n, err := plaintextFile.Read(buffer)
		if n > 0 {
			sealed := gcm.Seal(nil, nonce, buffer[:n], nil)
			if _, writeErr := ciphertextFile.Write(sealed); writeErr != nil {
				_ = os.Remove(encryptedTempFilePath)
				return "", nil, fmt.Errorf("failed to write encrypted chunk: %w", writeErr)
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			_ = os.Remove(encryptedTempFilePath)
			return "", nil, fmt.Errorf("failed to read plaintext file chunk: %w", err)
		}
	}

	// Remove the original plaintext file after successful encryption
	if err := os.Remove(filePath); err != nil {
		log.Warn("Failed to remove original file after encryption", "file", filePath, "error", err)
	}

	return encryptedTempFilePath, nonce, nil
}

// decryptFile decrypts a file encrypted with AES256-GCM and returns the path to the decrypted temporary file.
// The original encrypted file is removed after successful decryption.
func (qm *QuarantineManager) decryptFile(filePath string, key []byte, nonce []byte) (string, error) {
	ciphertextFile, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open ciphertext file %s: %w", filePath, err)
	}
	defer ciphertextFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Ensure nonce matches the expected size (this is handled during generation and storage)
	if len(nonce) != gcm.NonceSize() {
		return "", fmt.Errorf("invalid nonce size, expected %d, got %d", gcm.NonceSize(), len(nonce))
	}

	// Create a temporary file for the decrypted content
	decryptedTempFilePath := filePath + ".dec.tmp"

	plaintextFile, err := os.Create(decryptedTempFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create plaintext file %s: %w", decryptedTempFilePath, err)
	}
	defer plaintextFile.Close()

	// Stream decryption
	// The GCM sealed output includes the ciphertext and the authentication tag.
	// The buffer size must account for this overhead.
	buffer := make([]byte, chunkSize+gcm.Overhead())

	for {
		n, err := ciphertextFile.Read(buffer)
		if n > 0 {
			// Open the sealed data. The nonce is provided separately.
			opened, openErr := gcm.Open(nil, nonce, buffer[:n], nil)
			if openErr != nil {
				_ = os.Remove(decryptedTempFilePath) // Clean up on decryption error
				return "", fmt.Errorf("failed to decrypt chunk: %w", openErr)
			}

			if _, writeErr := plaintextFile.Write(opened); writeErr != nil {
				_ = os.Remove(decryptedTempFilePath) // Clean up on write error
				return "", fmt.Errorf("failed to write decrypted chunk: %w", writeErr)
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			_ = os.Remove(decryptedTempFilePath) // Clean up on read error
			return "", fmt.Errorf("failed to read ciphertext file chunk: %w", err)
		}
	}

	// Remove the original encrypted file after successful decryption
	if err := os.Remove(filePath); err != nil {
		log.Warn("Failed to remove original encrypted file after decryption", "file", filePath, "error", err)
	}

	return decryptedTempFilePath, nil
}

// encryptKeyWithMaster encrypts a file-specific key using the master key (AES256-GCM).
// The nonce is prepended to the ciphertext for simpler storage.
func (qm *QuarantineManager) encryptKeyWithMaster(fileKey, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher with master key: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM with master key: %w", err)
	}

	// Generate a new random nonce for the master key encryption
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for master key encryption: %w", err)
	}

	// Seal the fileKey with the master key's GCM and prepend the nonce
	sealed := gcm.Seal(nonce, nonce, fileKey, nil) // Nonce is prepended to output
	return sealed, nil
}

// decryptKeyWithMaster decrypts a file-specific key using the master key (AES256-GCM).
// It expects the nonce to be prepended to the encryptedFileKeyWithNonce.
func (qm *QuarantineManager) decryptKeyWithMaster(encryptedFileKeyWithNonce, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher with master key for decryption: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM with master key for decryption: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedFileKeyWithNonce) < nonceSize {
		return nil, fmt.Errorf("encrypted key too short to contain nonce")
	}

	// Extract nonce and ciphertext
	nonce := encryptedFileKeyWithNonce[:nonceSize]
	ciphertext := encryptedFileKeyWithNonce[nonceSize:]

	// Open the sealed data
	opened, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key with master key: %w", err)
	}

	return opened, nil
}

// moveFile moves a file from src to dst. It first attempts an atomic os.Rename,
// and if that fails with a cross-device link error (EXDEV), it falls back to
// a streaming copy followed by removal of the source file.
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	// Check if the error is a cross-device link error
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) {
		return err
	}

	if !errors.Is(linkErr.Err, syscall.EXDEV) {
		return err
	}

	// Cross-device: fall back to copy + delete
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file for copy: %w", err)
	}
	defer srcFile.Close()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat source file: %w", err)
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("failed to copy file content: %w", err)
	}

	// Ensure data is flushed to disk before removing the source
	if err := dstFile.Sync(); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	// Close both files before removing the source
	srcFile.Close()
	dstFile.Close()

	if err := os.Remove(src); err != nil {
		log.Warn("Failed to remove source file after cross-device move", "src", src, "error", err)
	}

	return nil
}

// deriveMasterKey converts a plain string encryption key from the config into
// a 32-byte AES-256 key by hashing it with SHA-256. This allows users to set
// any arbitrary string as the encryption key without worrying about exact
// length or hex encoding — the SHA-256 hash always produces exactly 32 bytes.
func deriveMasterKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}
