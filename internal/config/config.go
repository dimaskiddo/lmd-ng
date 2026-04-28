package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	App        AppConfig        `yaml:"app" mapstructure:"app"`
	Logging    LoggingConfig    `yaml:"logging" mapstructure:"logging"`
	Monitor    MonitorConfig    `yaml:"monitor" mapstructure:"monitor"`
	Quarantine QuarantineConfig `yaml:"quarantine" mapstructure:"quarantine"`
	Scanner    ScannerConfig    `yaml:"scanner" mapstructure:"scanner"`
	Scheduler  SchedulerConfig  `yaml:"scheduler" mapstructure:"scheduler"`
	Updater    UpdaterConfig    `yaml:"updater" mapstructure:"updater"`
}

// AppConfig holds application-wide settings.
type AppConfig struct {
	BasePath      string `yaml:"base_path" mapstructure:"base_path"`
	SignaturesDir string `yaml:"signatures_dir" mapstructure:"signatures_dir"`
	ClamAVDir     string `yaml:"clamav_dir" mapstructure:"clamav_dir"`
	QuarantineDir string `yaml:"quarantine_dir" mapstructure:"quarantine_dir"`
	LogsDir       string `yaml:"logs_dir" mapstructure:"logs_dir"`
}

// LoggingConfig holds logging-related settings.
type LoggingConfig struct {
	Level      string `yaml:"level" mapstructure:"level"`
	Output     string `yaml:"output" mapstructure:"output"`
	FilePath   string `yaml:"filepath" mapstructure:"filepath"`
	MaxSize    int    `yaml:"max_size" mapstructure:"max_size"`
	MaxBackups int    `yaml:"max_backups" mapstructure:"max_backups"`
	MaxAge     int    `yaml:"max_age" mapstructure:"max_age"`
	Compress   bool   `yaml:"compress" mapstructure:"compress"`
}

// MonitorConfig holds file system monitoring settings.
type MonitorConfig struct {
	Paths       []string `yaml:"paths" mapstructure:"paths"`
	ExcludeDirs []string `yaml:"exclude_dirs" mapstructure:"exclude_dirs"`
}

// QuarantineConfig holds quarantine-related settings.
type QuarantineConfig struct {
	Enabled          bool   `yaml:"enabled" mapstructure:"enabled"`
	Path             string `yaml:"path" mapstructure:"path"`
	EnableEncryption bool   `yaml:"enable_encryption" mapstructure:"enable_encryption"`
	EncryptionKey    string `yaml:"encryption_key" mapstructure:"encryption_key"`
}

// ScannerConfig holds malware scanning settings.
type ScannerConfig struct {
	SignaturePath  string   `yaml:"signature_path" mapstructure:"signature_path"`
	ClamAVEnabled  bool     `yaml:"clamav_enabled" mapstructure:"clamav_enabled"`
	ClamAVDBPath   string   `yaml:"clamav_db_path" mapstructure:"clamav_db_path"`
	ClamAVHexDepth int      `yaml:"clamav_hex_depth" mapstructure:"clamav_hex_depth"`
	MaxFilesize    string   `yaml:"max_filesize" mapstructure:"max_filesize"`
	MinFilesize    int64    `yaml:"min_filesize" mapstructure:"min_filesize"`
	MaxDepth       int      `yaml:"max_depth" mapstructure:"max_depth"`
	HexDepth       int      `yaml:"hex_depth" mapstructure:"hex_depth"`
	CPULimit       int      `yaml:"cpu_limit" mapstructure:"cpu_limit"`
	IgnoreRoot     bool     `yaml:"ignore_root" mapstructure:"ignore_root"`
	IgnoreUsers    []string `yaml:"ignore_users" mapstructure:"ignore_users"`
	IgnoreGroups   []string `yaml:"ignore_groups" mapstructure:"ignore_groups"`
	IncludeRegex   string   `yaml:"include_regex" mapstructure:"include_regex"`
	ExcludeRegex   string   `yaml:"exclude_regex" mapstructure:"exclude_regex"`
}

// SchedulerConfig holds scheduling settings for updates and scans.
type SchedulerConfig struct {
	UpdateInterval string `yaml:"update_interval" mapstructure:"update_interval"`
	ScanInterval   string `yaml:"scan_interval" mapstructure:"scan_interval"`
}

// UpdaterConfig holds signature updater settings.
type UpdaterConfig struct {
	AutoUpdateSignatures bool     `yaml:"auto_update_signatures" mapstructure:"auto_update_signatures"`
	RemoteURITimeout     string   `yaml:"remote_uri_timeout" mapstructure:"remote_uri_timeout"`
	SignaturePackURL     string   `yaml:"signature_pack_url" mapstructure:"signature_pack_url"`
	SignatureVersionURL  string   `yaml:"signature_version_url" mapstructure:"signature_version_url"`
	ClamAVUpdateEnabled  bool     `yaml:"clamav_update_enabled" mapstructure:"clamav_update_enabled"`
	ClamAVMirrorURL      string   `yaml:"clamav_mirror_url" mapstructure:"clamav_mirror_url"`
	ClamAVDatabases      []string `yaml:"clamav_databases" mapstructure:"clamav_databases"`
}

// SetDefaultConfig sets default values for the configuration.
// NOTE: BasePath is intentionally left as "." here as a compile-time
// placeholder. NewConfigManager always overrides BasePath with the directory
// that contains the running binary (via os.Executable), so sub-directory
// defaults derived from it are also immediately re-derived there. This
// function is therefore only responsible for setting non-path defaults.
func SetDefaultConfig(config *Config) {
	config.App.BasePath = "."
	config.App.SignaturesDir = filepath.Join(config.App.BasePath, "sigs")
	config.App.ClamAVDir = filepath.Join(config.App.BasePath, "clamav")
	config.App.QuarantineDir = filepath.Join(config.App.BasePath, "quarantine")
	config.App.LogsDir = filepath.Join(config.App.BasePath, "logs")

	config.Logging.Level = "info"
	config.Logging.Output = "file"
	config.Logging.FilePath = filepath.Join(config.App.LogsDir, "lmd-ng.log")
	config.Logging.MaxSize = 10
	config.Logging.MaxBackups = 7
	config.Logging.MaxAge = 1
	config.Logging.Compress = true

	config.Monitor.Paths = []string{"/home", "/var/www"}
	config.Monitor.ExcludeDirs = []string{"/proc", "/sys", "/dev"}

	config.Quarantine.Enabled = true
	config.Quarantine.Path = config.App.QuarantineDir
	config.Quarantine.EnableEncryption = true
	config.Quarantine.EncryptionKey = "CHANGE-THIS-TO-YOUR-SECRET-KEY"

	config.Scanner.SignaturePath = config.App.SignaturesDir

	config.Scanner.ClamAVEnabled = false
	config.Scanner.ClamAVDBPath = config.App.ClamAVDir
	config.Scanner.ClamAVHexDepth = 65536

	config.Scanner.MinFilesize = 0
	config.Scanner.MaxFilesize = "20M"
	config.Scanner.MaxDepth = 0
	config.Scanner.HexDepth = 20000
	config.Scanner.CPULimit = 0

	config.Scanner.IgnoreRoot = false
	config.Scanner.IgnoreUsers = []string{"root"}
	config.Scanner.IgnoreGroups = []string{"root"}

	config.Scanner.IncludeRegex = ""
	config.Scanner.ExcludeRegex = ""

	config.Scheduler.UpdateInterval = "@daily"
	config.Scheduler.ScanInterval = "@every 4h"

	config.Updater.AutoUpdateSignatures = true
	config.Updater.RemoteURITimeout = "30s"

	config.Updater.SignaturePackURL = "https://www.rfxn.com/downloads/maldet-sigpack.tgz"
	config.Updater.SignatureVersionURL = "https://www.rfxn.com/downloads/maldet-sigpack.ver"

	config.Updater.ClamAVUpdateEnabled = false
	config.Updater.ClamAVMirrorURL = "https://database.clamav.net"
	config.Updater.ClamAVDatabases = []string{"daily.cvd", "bytecode.cvd", "main.cvd"}
}

// EnsureDirectories creates all required application directories based on
// the current configuration. This should be called once during startup to
// guarantee the directory tree exists regardless of how the binary was
// deployed. Directories created: logs, signatures, quarantine, and clamav.
func EnsureDirectories(cfg *Config) error {
	dirs := []struct {
		path string
		name string
	}{
		{cfg.Logging.FilePath, "logs"},
		{cfg.Scanner.SignaturePath, "signatures"},
		{cfg.Quarantine.Path, "quarantine"},
	}

	// Add ClamAV directory only if ClamAV is enabled
	if cfg.Scanner.ClamAVEnabled {
		dirs = append(dirs, struct {
			path string
			name string
		}{cfg.Scanner.ClamAVDBPath, "clamav"})
	}

	for _, d := range dirs {
		dirPath := d.path

		// For file paths (like log filepath), extract the directory
		if d.name == "logs" {
			dirPath = filepath.Dir(dirPath)
		}

		// Resolve relative paths against BasePath
		if !filepath.IsAbs(dirPath) {
			dirPath = filepath.Join(cfg.App.BasePath, dirPath)
		}

		if err := os.MkdirAll(dirPath, 0755); err != nil {
			return fmt.Errorf("failed to create %s directory %s: %w", d.name, dirPath, err)
		}
	}

	return nil
}

// HasSignatures checks whether the LMD signature database directory contains
// any signature files. Returns true if at least one .dat file is found in
// the configured signatures path, indicating a previous successful update.
func HasSignatures(cfg *Config) bool {
	sigPath := cfg.Scanner.SignaturePath
	if !filepath.IsAbs(sigPath) {
		sigPath = filepath.Join(cfg.App.BasePath, sigPath)
	}

	// Check for the dat/ subdirectory which contains core LMD signatures
	datDir := filepath.Join(sigPath, "dat")
	entries, err := os.ReadDir(datDir)
	if err != nil {
		// Directory doesn't exist or can't be read — no signatures
		return false
	}

	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".dat" {
			return true
		}
	}

	return false
}
