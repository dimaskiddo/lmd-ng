package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type Config struct {
	App          AppConfig          `yaml:"app" mapstructure:"app"`
	Logging      LoggingConfig      `yaml:"logging" mapstructure:"logging"`
	Server       ServerConfig       `yaml:"server" mapstructure:"server"`
	Monitor      MonitorConfig      `yaml:"monitor" mapstructure:"monitor"`
	Quarantine   QuarantineConfig   `yaml:"quarantine" mapstructure:"quarantine"`
	Scanner      ScannerConfig      `yaml:"scanner" mapstructure:"scanner"`
	Scheduler    SchedulerConfig    `yaml:"scheduler" mapstructure:"scheduler"`
	Updater      UpdaterConfig      `yaml:"updater" mapstructure:"updater"`
	Notification NotificationConfig `yaml:"notification" mapstructure:"notification"`
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

// ServerConfig holds DBS server/client connection configuration.
type ServerConfig struct {
	Network    string    `yaml:"network" mapstructure:"network"`         // "unix" or "tcp" (default: "unix")
	SocketPath string    `yaml:"socket_path" mapstructure:"socket_path"` // Unix socket path
	Address    string    `yaml:"address" mapstructure:"address"`         // TCP listen address
	TLS        TLSConfig `yaml:"tls" mapstructure:"tls"`
}

// TLSConfig holds mutual TLS settings. TLS is always enabled — there is no
// toggle. Communication between DBS server and clients is always encrypted.
type TLSConfig struct {
	CertFile string `yaml:"cert_file" mapstructure:"cert_file"` // Server certificate path
	KeyFile  string `yaml:"key_file" mapstructure:"key_file"`   // Server key path
	CAFile   string `yaml:"ca_file" mapstructure:"ca_file"`     // CA certificate for verification
	AutoCert bool   `yaml:"auto_cert" mapstructure:"auto_cert"` // Auto-generate self-signed certs (default: true)
	CertsDir string `yaml:"certs_dir" mapstructure:"certs_dir"` // Directory for auto-generated certs
}

// QuarantineConfig holds quarantine-related settings.
type QuarantineConfig struct {
	Enabled          bool   `yaml:"enabled" mapstructure:"enabled"`
	Path             string `yaml:"path" mapstructure:"path"`
	EnableEncryption bool   `yaml:"enable_encryption" mapstructure:"enable_encryption"`
	EncryptionKey    string `yaml:"encryption_key" mapstructure:"encryption_key"`
}

// MonitorConfig holds file system monitoring settings.
type MonitorConfig struct {
	Paths       []string `yaml:"paths" mapstructure:"paths"`
	ExcludeDirs []string `yaml:"exclude_dirs" mapstructure:"exclude_dirs"`
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
	// HashAllowlistPaths is an optional list of path prefixes under which
	// MD5 and SHA256 hash-engine detections are suppressed. This guards
	// against a bad signature database containing hashes of legitimate
	// system files. Leave empty (default) to disable the allowlist and
	// report all hash matches regardless of file location.
	HashAllowlistPaths []string `yaml:"hash_allowlist_paths" mapstructure:"hash_allowlist_paths"`
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

// NotificationConfig holds notification settings.
type NotificationConfig struct {
	Email    EmailNotificationConfig    `yaml:"email" mapstructure:"email"`
	Telegram TelegramNotificationConfig `yaml:"telegram" mapstructure:"telegram"`
}

// EmailNotificationConfig holds email notification settings.
type EmailNotificationConfig struct {
	Enabled       bool     `yaml:"enabled" mapstructure:"enabled"`
	SMTPHost      string   `yaml:"smtp_host" mapstructure:"smtp_host"`
	SMTPPort      int      `yaml:"smtp_port" mapstructure:"smtp_port"`
	SMTPUsername  string   `yaml:"smtp_username" mapstructure:"smtp_username"`
	SMTPPassword  string   `yaml:"smtp_password" mapstructure:"smtp_password"`
	SMTPUseSSLTLS bool     `yaml:"smtp_use_ssl_tls" mapstructure:"smtp_use_ssl_tls"`
	Sender        string   `yaml:"sender" mapstructure:"sender"`
	Recipients    []string `yaml:"recipients" mapstructure:"recipients"`
}

// TelegramNotificationConfig holds Telegram notification settings.
type TelegramNotificationConfig struct {
	Enabled  bool   `yaml:"enabled" mapstructure:"enabled"`
	BotToken string `yaml:"bot_token" mapstructure:"bot_token"`
	ChatID   string `yaml:"chat_id" mapstructure:"chat_id"`
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

	config.Server.Network = "unix"
	config.Server.SocketPath = filepath.Join(config.App.BasePath, "lmd-ng.sock")
	config.Server.Address = "127.0.0.1:7890"

	config.Server.TLS.AutoCert = true
	config.Server.TLS.CertsDir = filepath.Join(config.App.BasePath, "certs")

	config.Quarantine.Enabled = true
	config.Quarantine.Path = config.App.QuarantineDir
	config.Quarantine.EnableEncryption = true
	config.Quarantine.EncryptionKey = "CHANGE-THIS-TO-YOUR-SECRET-KEY"

	config.Monitor.Paths = []string{"/home", "/var/www"}
	config.Monitor.ExcludeDirs = []string{"/proc", "/sys", "/dev"}

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
	config.Scanner.HashAllowlistPaths = []string{}

	config.Scheduler.UpdateInterval = "@daily"
	config.Scheduler.ScanInterval = "@every 4h"

	config.Updater.AutoUpdateSignatures = true
	config.Updater.RemoteURITimeout = "30s"

	config.Updater.SignaturePackURL = "https://www.rfxn.com/downloads/maldet-sigpack.tgz"
	config.Updater.SignatureVersionURL = "https://www.rfxn.com/downloads/maldet-sigpack.ver"

	config.Updater.ClamAVUpdateEnabled = false
	config.Updater.ClamAVMirrorURL = "https://database.clamav.net"
	config.Updater.ClamAVDatabases = []string{"daily.cvd", "bytecode.cvd", "main.cvd"}

	config.Notification.Email.Enabled = false
	config.Notification.Email.SMTPHost = "smtp.example.com"
	config.Notification.Email.SMTPPort = 587
	config.Notification.Email.SMTPUsername = "user@example.com"
	config.Notification.Email.SMTPPassword = "secretpassword"
	config.Notification.Email.SMTPUseSSLTLS = false
	config.Notification.Email.Sender = "lmd-ng@example.com"
	config.Notification.Email.Recipients = []string{"admin@example.com"}

	config.Notification.Telegram.Enabled = false
	config.Notification.Telegram.BotToken = "YOUR_TELEGRAM_BOT_TOKEN"
	config.Notification.Telegram.ChatID = "YOUR_TELEGRAM_CHAT_ID"
}

// ResolvePaths ensures all directory and file paths in the configuration
// are absolute. Any relative paths are resolved against the App.BasePath.
func (c *Config) ResolvePaths() {
	resolve := func(path *string) {
		if *path != "" && !filepath.IsAbs(*path) {
			*path = filepath.Join(c.App.BasePath, *path)
		}
	}

	resolve(&c.App.SignaturesDir)
	resolve(&c.App.ClamAVDir)
	resolve(&c.App.QuarantineDir)
	resolve(&c.App.LogsDir)

	resolve(&c.Logging.FilePath)

	resolve(&c.Server.SocketPath)
	resolve(&c.Server.TLS.CertsDir)
	resolve(&c.Server.TLS.CertFile)
	resolve(&c.Server.TLS.KeyFile)
	resolve(&c.Server.TLS.CAFile)

	resolve(&c.Quarantine.Path)

	resolve(&c.Scanner.SignaturePath)
	resolve(&c.Scanner.ClamAVDBPath)
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
