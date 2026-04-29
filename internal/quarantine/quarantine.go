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
	"time"

	"github.com/dimaskiddo/lmd-ng/internal/config"
	"github.com/dimaskiddo/lmd-ng/internal/log"
)

const (
	filePerm  = 0o000 // Read/write/execute denied for all
	chunkSize = 4096  // 4KB chunk size for stream encryption/decryption
)

// Metadata stores information about a quarantined file.
// All POSIX file attributes needed for a bit-perfect restore are captured here.
type Metadata struct {
	// Identity
	OriginalPath    string `json:"original_path"`
	QuarantinePath  string `json:"quarantine_path"`
	DetectionInfo   string `json:"detection_info"`
	DetectionEngine string `json:"detection_engine,omitempty"`

	// POSIX file attributes — captured before the file is moved/encrypted.
	FileMode    uint32    `json:"file_mode"`            // Full os.FileMode bits as uint32
	FileModeStr string    `json:"file_mode_str"`        // Human-readable e.g. "-rwsr-xr-x"
	UID         uint32    `json:"uid"`                  // Owner user ID (0 on Windows)
	GID         uint32    `json:"gid"`                  // Owner group ID (0 on Windows)
	Username    string    `json:"username,omitempty"`   // Resolved username (best-effort)
	GroupName   string    `json:"group_name,omitempty"` // Resolved group name (best-effort)
	ModTime     time.Time `json:"mod_time"`             // Original modification time
	FileSize    int64     `json:"file_size"`            // Original file size in bytes

	// Quarantine event info
	QuarantinedAt time.Time `json:"quarantined_at"`

	// Crypto fields (omitempty so non-encrypted entries stay clean)
	EncryptionKey []byte `json:"encryption_key,omitempty"`
	Nonce         []byte `json:"nonce,omitempty"`
}

// ListEntry is a summary of a single quarantined file returned by List.
type ListEntry struct {
	ID              string
	ShortID         string
	OriginalPath    string
	QuarantinePath  string
	DetectionInfo   string
	DetectionEngine string
	Encrypted       bool
	FileMode        string
	Username        string
	GroupName       string
	QuarantinedAt   time.Time
}

// Manager defines the interface for quarantine operations.
type Manager interface {
	Quarantine(ctx context.Context, filePath string, detectionInfo string, detectionEngine string) (string, error)
	Restore(ctx context.Context, quarantinePath string) (string, error)
	List(ctx context.Context) ([]ListEntry, error)
	ResolveByID(id string) (string, error)
	Remove(ctx context.Context, quarantinePath string) error
}

// QuarantineManager implements the Manager interface.
type QuarantineManager struct {
	cfg *config.QuarantineConfig
}

// NewQuarantineManager creates a new QuarantineManager.
func NewQuarantineManager(cfg *config.QuarantineConfig) *QuarantineManager {
	return &QuarantineManager{cfg: cfg}
}

// Quarantine moves a file to quarantine, captures its full POSIX metadata,
// sets restrictive permissions, and optionally encrypts it.
func (qm *QuarantineManager) Quarantine(ctx context.Context, filePath string, detectionInfo string, detectionEngine string) (string, error) {
	if err := os.MkdirAll(qm.cfg.Path, 0o700); err != nil {
		return "", fmt.Errorf("failed to create quarantine directory %s: %w", qm.cfg.Path, err)
	}

	// Capture file attributes BEFORE moving (Lstat to avoid following symlinks).
	info, err := os.Lstat(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to stat file %s before quarantine: %w", filePath, err)
	}

	uid, gid, username, groupName := captureOwnership(info)

	metadata := Metadata{
		OriginalPath:    filePath,
		DetectionInfo:   detectionInfo,
		DetectionEngine: detectionEngine,
		FileMode:        uint32(info.Mode()),
		FileModeStr:     info.Mode().String(),
		UID:             uid,
		GID:             gid,
		Username:        username,
		GroupName:       groupName,
		ModTime:         info.ModTime(),
		FileSize:        info.Size(),
		QuarantinedAt:   time.Now(),
	}

	// Generate unique quarantine filename
	uniqueIDBytes := make([]byte, 16)
	if _, err := rand.Read(uniqueIDBytes); err != nil {
		return "", fmt.Errorf("failed to generate unique quarantine ID: %w", err)
	}

	uniqueID := hex.EncodeToString(uniqueIDBytes)
	quarantineFileName := fmt.Sprintf("%s.%s.quarantined", filepath.Base(filePath), uniqueID)
	quarantinePath := filepath.Join(qm.cfg.Path, quarantineFileName)
	finalQuarantinePath := quarantinePath

	if qm.cfg.EnableEncryption {
		if qm.cfg.EncryptionKey == "" {
			return "", fmt.Errorf("quarantine encryption is enabled but encryption_key is empty in config")
		}
		masterKey := deriveMasterKey(qm.cfg.EncryptionKey)
		fileKey := make([]byte, 32)
		if _, err := rand.Read(fileKey); err != nil {
			return "", fmt.Errorf("failed to generate file encryption key: %w", err)
		}

		encryptedFilePath, nonce, err := qm.encryptFile(filePath, fileKey)
		if err != nil {
			log.Error("Failed to encrypt file, quarantining unencrypted", "file", filePath, "error", err)

			if moveErr := moveFile(filePath, quarantinePath); moveErr != nil {
				return "", fmt.Errorf("failed to move file to quarantine after encryption failure: %w", moveErr)
			}

			metadata.QuarantinePath = quarantinePath
		} else {
			if err := moveFile(encryptedFilePath, quarantinePath); err != nil {
				return "", fmt.Errorf("failed to move encrypted file to quarantine: %w", err)
			}

			encryptedFileKey, err := qm.encryptKeyWithMaster(fileKey, masterKey)
			if err != nil {
				_ = os.Remove(quarantinePath)
				return "", fmt.Errorf("failed to encrypt file key with master key: %w", err)
			}

			metadata.EncryptionKey = encryptedFileKey
			metadata.Nonce = nonce
			metadata.QuarantinePath = quarantinePath
		}
	} else {
		if err := moveFile(filePath, quarantinePath); err != nil {
			return "", fmt.Errorf("failed to move file %s to quarantine: %w", filePath, err)
		}

		metadata.QuarantinePath = quarantinePath
	}

	// Lock down the quarantined file
	if err := os.Chmod(finalQuarantinePath, filePerm); err != nil {
		log.Warn("Failed to set restrictive permissions on quarantined file", "file", finalQuarantinePath, "error", err)
	}

	// Write metadata sidecar
	metadataFilePath := finalQuarantinePath + ".metadata.json"
	metadataBytes, err := json.MarshalIndent(metadata, "", "  ")

	if err != nil {
		_ = os.Remove(finalQuarantinePath)
		return "", fmt.Errorf("failed to marshal quarantine metadata: %w", err)
	}

	if err := os.WriteFile(metadataFilePath, metadataBytes, 0o600); err != nil {
		_ = os.Remove(finalQuarantinePath)
		_ = os.Remove(metadataFilePath)
		return "", fmt.Errorf("failed to write quarantine metadata file: %w", err)
	}

	log.Info("File quarantined",
		"original_path", filePath,
		"quarantine_path", finalQuarantinePath,
		"detection_info", detectionInfo,
		"detection_engine", detectionEngine,
		"mode", metadata.FileModeStr,
		"owner", fmt.Sprintf("%s(%d):%s(%d)", username, uid, groupName, gid),
		"encrypted", qm.cfg.EnableEncryption)

	return finalQuarantinePath, nil
}

// Restore moves a quarantined file back to its original path, decrypts it if
// necessary, and faithfully restores all POSIX attributes: mode bits (including
// setuid/setgid/sticky), ownership (UID/GID), and modification time.
func (qm *QuarantineManager) Restore(ctx context.Context, quarantinePath string) (string, error) {
	metadataFilePath := quarantinePath + ".metadata.json"
	metadataBytes, err := os.ReadFile(metadataFilePath)

	if os.IsNotExist(err) {
		return "", fmt.Errorf("quarantine metadata file not found for %s: %w", quarantinePath, err)
	}

	if err != nil {
		return "", fmt.Errorf("failed to read quarantine metadata file %s: %w", metadataFilePath, err)
	}

	var metadata Metadata
	if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
		return "", fmt.Errorf("failed to unmarshal quarantine metadata: %w", err)
	}

	// Temporarily grant owner-read to open the locked file
	if err := os.Chmod(quarantinePath, 0o400); err != nil {
		return "", fmt.Errorf("failed to grant read permission on quarantined file before restore: %w", err)
	}

	lockDown := func() {
		if chmodErr := os.Chmod(quarantinePath, filePerm); chmodErr != nil {
			log.Warn("Failed to re-lock quarantined file after restore error", "file", quarantinePath, "error", chmodErr)
		}
	}

	fileToRestorePath := quarantinePath

	if qm.cfg.EnableEncryption && len(metadata.EncryptionKey) > 0 && len(metadata.Nonce) > 0 {
		if qm.cfg.EncryptionKey == "" {
			lockDown()
			return "", fmt.Errorf("quarantine encryption is enabled but encryption_key is empty in config")
		}

		masterKey := deriveMasterKey(qm.cfg.EncryptionKey)
		fileKey, err := qm.decryptKeyWithMaster(metadata.EncryptionKey, masterKey)

		if err != nil {
			lockDown()
			return "", fmt.Errorf("failed to decrypt file encryption key: %w", err)
		}

		decryptedFilePath, err := qm.decryptFile(quarantinePath, fileKey, metadata.Nonce)

		if err != nil {
			lockDown()
			return "", fmt.Errorf("failed to decrypt quarantined file: %w", err)
		}

		fileToRestorePath = decryptedFilePath
	}

	// Ensure the parent directory of the original path exists
	if err := os.MkdirAll(filepath.Dir(metadata.OriginalPath), 0o755); err != nil {
		lockDown()
		return "", fmt.Errorf("failed to recreate parent directory for %s: %w", metadata.OriginalPath, err)
	}

	// Move back to original path
	if err := moveFile(fileToRestorePath, metadata.OriginalPath); err != nil {
		lockDown()
		return "", fmt.Errorf("failed to move file to original path %s: %w", metadata.OriginalPath, err)
	}

	// --- Restore POSIX attributes ---
	// 1. Restore full mode bits (rwxrwxrwx + setuid + setgid + sticky).
	//    Fallback to 0644 if no mode was recorded (old metadata schema).
	restoreMode := os.FileMode(metadata.FileMode)
	if restoreMode == 0 {
		restoreMode = 0o644
	}

	if err := os.Chmod(metadata.OriginalPath, restoreMode); err != nil {
		log.Warn("Failed to restore file mode", "file", metadata.OriginalPath, "mode", restoreMode, "error", err)
	}

	// 2. Restore ownership (requires root/CAP_CHOWN; only skip, never abort).
	if metadata.UID != 0 || metadata.GID != 0 {
		if err := applyOwnership(metadata.OriginalPath, metadata.UID, metadata.GID); err != nil {
			log.Warn("Failed to restore file ownership (requires root) — skipping",
				"file", metadata.OriginalPath,
				"uid", metadata.UID,
				"gid", metadata.GID,
				"error", err)
		}
	}

	// 3. Restore modification time (atime=now, mtime=original).
	if !metadata.ModTime.IsZero() {
		if err := os.Chtimes(metadata.OriginalPath, time.Now(), metadata.ModTime); err != nil {
			log.Warn("Failed to restore file modification time", "file", metadata.OriginalPath, "error", err)
		}
	}

	log.Info("File restored",
		"quarantine_path", quarantinePath,
		"original_path", metadata.OriginalPath,
		"mode_restored", restoreMode.String())

	// Clean up quarantine artefacts
	if err := os.Remove(quarantinePath); err != nil && !os.IsNotExist(err) {
		log.Warn("Failed to remove quarantined file after restoration", "file", quarantinePath, "error", err)
	}

	if err := os.Remove(metadataFilePath); err != nil && !os.IsNotExist(err) {
		log.Warn("Failed to remove metadata file after restoration", "file", metadataFilePath, "error", err)
	}

	return metadata.OriginalPath, nil
}

// List returns a summary of all quarantined files.
func (qm *QuarantineManager) List(ctx context.Context) ([]ListEntry, error) {
	entries, err := os.ReadDir(qm.cfg.Path)
	if err != nil {
		if os.IsNotExist(err) {
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

		baseName := strings.TrimSuffix(name, ".quarantined.metadata.json")

		id := ""
		if idx := strings.LastIndex(baseName, "."); idx >= 0 {
			id = baseName[idx+1:]
		}

		shortID := id
		if len(id) >= 8 {
			shortID = id[:8]
		}

		list = append(list, ListEntry{
			ID:              id,
			ShortID:         shortID,
			OriginalPath:    meta.OriginalPath,
			QuarantinePath:  meta.QuarantinePath,
			DetectionInfo:   meta.DetectionInfo,
			DetectionEngine: meta.DetectionEngine,
			Encrypted:       len(meta.EncryptionKey) > 0 && len(meta.Nonce) > 0,
			FileMode:        meta.FileModeStr,
			Username:        meta.Username,
			GroupName:       meta.GroupName,
			QuarantinedAt:   meta.QuarantinedAt,
		})
	}

	return list, nil
}

// ResolveByID resolves a quarantine path from an absolute path, full ID, or short ID prefix.
func (qm *QuarantineManager) ResolveByID(id string) (string, error) {
	if filepath.IsAbs(id) {
		if _, err := os.Stat(id); err == nil {
			return id, nil
		}
	}

	if len(id) < 4 {
		return "", fmt.Errorf("ID %q is too short; provide at least 4 characters", id)
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
		return "", fmt.Errorf("ambiguous ID %q matches %d entries; use more characters", id, len(matches))
	}
}

// Remove permanently deletes a quarantined file and its metadata sidecar.
func (qm *QuarantineManager) Remove(ctx context.Context, quarantinePath string) error {
	metadataFilePath := quarantinePath + ".metadata.json"

	if _, err := os.Stat(quarantinePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("quarantined file not found: %s", quarantinePath)
		}

		return fmt.Errorf("failed to stat quarantined file %s: %w", quarantinePath, err)
	}

	if err := os.Chmod(quarantinePath, 0o200); err != nil {
		return fmt.Errorf("failed to grant write permission on quarantined file before removal: %w", err)
	}

	if err := os.Remove(quarantinePath); err != nil {
		if chmodErr := os.Chmod(quarantinePath, filePerm); chmodErr != nil {
			log.Warn("Failed to re-lock quarantined file after removal error", "file", quarantinePath, "error", chmodErr)
		}

		return fmt.Errorf("failed to remove quarantined file %s: %w", quarantinePath, err)
	}

	if err := os.Remove(metadataFilePath); err != nil && !os.IsNotExist(err) {
		log.Warn("Failed to remove quarantine metadata file", "file", metadataFilePath, "error", err)
	}

	log.Info("Quarantined file permanently removed", "quarantine_path", quarantinePath)
	return nil
}

// --- Encryption helpers ---

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

	encryptedTempFilePath := filePath + ".enc.tmp"

	ciphertextFile, err := os.Create(encryptedTempFilePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create ciphertext file: %w", err)
	}
	defer ciphertextFile.Close()

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

	if err := os.Remove(filePath); err != nil {
		log.Warn("Failed to remove original file after encryption", "file", filePath, "error", err)
	}

	return encryptedTempFilePath, nonce, nil
}

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

	if len(nonce) != gcm.NonceSize() {
		return "", fmt.Errorf("invalid nonce size: expected %d, got %d", gcm.NonceSize(), len(nonce))
	}

	decryptedTempFilePath := filePath + ".dec.tmp"
	plaintextFile, err := os.Create(decryptedTempFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to create plaintext file: %w", err)
	}
	defer plaintextFile.Close()

	buffer := make([]byte, chunkSize+gcm.Overhead())
	for {
		n, err := ciphertextFile.Read(buffer)
		if n > 0 {
			opened, openErr := gcm.Open(nil, nonce, buffer[:n], nil)
			if openErr != nil {
				_ = os.Remove(decryptedTempFilePath)
				return "", fmt.Errorf("failed to decrypt chunk: %w", openErr)
			}
			if _, writeErr := plaintextFile.Write(opened); writeErr != nil {
				_ = os.Remove(decryptedTempFilePath)
				return "", fmt.Errorf("failed to write decrypted chunk: %w", writeErr)
			}
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			_ = os.Remove(decryptedTempFilePath)
			return "", fmt.Errorf("failed to read ciphertext chunk: %w", err)
		}
	}

	if err := os.Remove(filePath); err != nil {
		log.Warn("Failed to remove encrypted file after decryption", "file", filePath, "error", err)
	}

	return decryptedTempFilePath, nil
}

func (qm *QuarantineManager) encryptKeyWithMaster(fileKey, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher with master key: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM with master key: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce for master key encryption: %w", err)
	}

	return gcm.Seal(nonce, nonce, fileKey, nil), nil
}

func (qm *QuarantineManager) decryptKeyWithMaster(encryptedFileKeyWithNonce, masterKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher with master key: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM with master key: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedFileKeyWithNonce) < nonceSize {
		return nil, fmt.Errorf("encrypted key too short to contain nonce")
	}

	nonce := encryptedFileKeyWithNonce[:nonceSize]
	ciphertext := encryptedFileKeyWithNonce[nonceSize:]

	opened, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key with master key: %w", err)
	}

	return opened, nil
}

// moveFile moves src to dst atomically or via copy+delete for cross-device moves.
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}

	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) {
		return err
	}

	if !errors.Is(linkErr.Err, syscall.EXDEV) {
		return err
	}

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

	if err := dstFile.Sync(); err != nil {
		_ = os.Remove(dst)
		return fmt.Errorf("failed to sync destination file: %w", err)
	}

	srcFile.Close()
	dstFile.Close()

	if err := os.Remove(src); err != nil {
		log.Warn("Failed to remove source file after cross-device move", "src", src, "error", err)
	}

	return nil
}

// deriveMasterKey converts a passphrase to a 32-byte AES-256 key via SHA-256.
func deriveMasterKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}
