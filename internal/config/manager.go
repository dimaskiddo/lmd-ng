package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

// executableDir returns the absolute directory that contains the running
// binary, following any symlinks. Falls back to the process working directory
// when the executable path cannot be determined.
func executableDir() string {
	exePath, err := os.Executable()
	if err != nil {
		// Fallback: use the current working directory
		cwd, wdErr := os.Getwd()
		if wdErr != nil {
			return "."
		}

		return cwd
	}

	// Resolve symlinks so that e.g. /usr/local/bin/lmd-ng -> /usr/local/lmd-ng/lmd-ng
	// is handled correctly.
	realPath, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		// If symlink resolution fails, use the raw executable path
		realPath = exePath
	}

	return filepath.Dir(realPath)
}

// Manager handles loading, parsing, and watching configuration.
type Manager struct {
	Viper            *viper.Viper
	Config           *Config
	ConfigChangeChan chan struct{}
}

// NewConfigManager creates a new configuration manager.
func NewConfigManager(configFilePath string) (*Manager, error) {
	m := &Manager{
		Viper:            viper.New(),
		Config:           &Config{},
		ConfigChangeChan: make(chan struct{}, 1),
	}

	// Resolve the binary's own directory first; all relative defaults are
	// anchored here so that lmd-ng works correctly regardless of the CWD
	// from which the operator invokes it.
	binDir := executableDir()

	// Set default values directly on the Config struct, using the binary
	// directory as the base path instead of "."
	SetDefaultConfig(m.Config)
	m.Config.App.BasePath = binDir

	// Re-derive subdirectory defaults that depend on BasePath so they also
	// point at the binary directory.
	m.Config.App.SignaturesDir = filepath.Join(binDir, "sigs")
	m.Config.App.ClamAVDir = filepath.Join(binDir, "clamav")
	m.Config.App.QuarantineDir = filepath.Join(binDir, "quarantine")
	m.Config.App.LogsDir = filepath.Join(binDir, "logs")

	m.Config.Logging.FilePath = filepath.Join(m.Config.App.LogsDir, "lmd-ng.log")

	m.Config.Server.SocketPath = filepath.Join(binDir, "lmd-ng.sock")
	m.Config.Server.TLS.CertsDir = filepath.Join(binDir, "certs")

	m.Config.Quarantine.Path = m.Config.App.QuarantineDir
	m.Config.Scanner.SignaturePath = m.Config.App.SignaturesDir
	m.Config.Scanner.ClamAVDBPath = m.Config.App.ClamAVDir

	// Configure Viper to read from the specified path or default locations
	if configFilePath != "" {
		m.Viper.SetConfigFile(configFilePath)
	} else {
		m.Viper.SetConfigName("config")
		m.Viper.SetConfigType("yaml")

		// Search order: binary's own directory first, then system-wide paths.
		// Deliberately excluded "."/CWD to avoid ambiguity when the operator
		// runs lmd-ng from an unrelated directory.
		m.Viper.AddConfigPath(binDir)
		m.Viper.AddConfigPath("/etc/lmd-ng/")
		m.Viper.AddConfigPath("/usr/local/etc/lmd-ng/")
		m.Viper.AddConfigPath("/usr/local/lmd-ng/")
	}

	// Read configuration
	if err := m.Viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found; ignore and use defaults
			log.Warn("Config file not found, using default configuration.")
		} else {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}

	// Unmarshal the config into the Config struct
	if err := m.Viper.Unmarshal(m.Config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// After Viper unmarshalling, if the config file set a relative BasePath
	// resolve it against the binary directory (not CWD) so it remains stable.
	if !filepath.IsAbs(m.Config.App.BasePath) {
		m.Config.App.BasePath = filepath.Join(binDir, m.Config.App.BasePath)
	}

	// Ensure all paths in the configuration are absolute, resolving any
	// relative paths against the potentially updated BasePath.
	m.Config.ResolvePaths()

	// Add app data directories to exclude list to prevent recursive monitoring loops
	// and to ensure the on-demand scanner doesn't scan its own data.
	appDirs := []string{
		m.Config.App.SignaturesDir,
		m.Config.App.ClamAVDir,
		m.Config.App.QuarantineDir,
		filepath.Dir(m.Config.Logging.FilePath), // Get directory of log file
	}

	for _, dir := range appDirs {
		if dir != "" {
			absDir, err := filepath.Abs(dir)
			if err == nil {
				// Avoid duplicates
				exists := false
				for _, e := range m.Config.Monitor.ExcludeDirs {
					if e == absDir {
						exists = true
						break
					}
				}

				if !exists {
					m.Config.Monitor.ExcludeDirs = append(m.Config.Monitor.ExcludeDirs, absDir)
				}
			}
		}
	}

	return m, nil
}

// WatchConfig watches for configuration file changes and hot-reloads.
func (m *Manager) WatchConfig(ctx context.Context) {
	m.Viper.OnConfigChange(func(e fsnotify.Event) {
		// Create a new Config struct to unmarshal into, to avoid issues with concurrent map writes
		newConfig := &Config{}

		// Set default values for the new config
		SetDefaultConfig(newConfig)

		if err := m.Viper.Unmarshal(newConfig); err != nil {
			return
		}

		// Update the manager's config with the new one
		m.Config = newConfig

		// Resolve absolute paths for application directories again,
		// anchoring relative paths to the binary directory rather than CWD.
		if !filepath.IsAbs(m.Config.App.BasePath) {
			m.Config.App.BasePath = filepath.Join(executableDir(), m.Config.App.BasePath)
		}

		// Ensure all paths in the configuration are absolute
		m.Config.ResolvePaths()

		// Add app data directories to exclude list to prevent recursive monitoring loops
		appDirs := []string{
			m.Config.App.SignaturesDir,
			m.Config.App.ClamAVDir,
			m.Config.App.QuarantineDir,
			filepath.Dir(m.Config.Logging.FilePath),
		}

		for _, dir := range appDirs {
			if dir != "" {
				absDir, err := filepath.Abs(dir)
				if err == nil {
					// Avoid duplicates
					exists := false
					for _, e := range m.Config.Monitor.ExcludeDirs {
						if e == absDir {
							exists = true
							break
						}
					}

					if !exists {
						m.Config.Monitor.ExcludeDirs = append(m.Config.Monitor.ExcludeDirs, absDir)
					}
				}
			}
		}

		// Notify listeners about config change
		select {
		case m.ConfigChangeChan <- struct{}{}:
		default:
		}
	})

	m.Viper.WatchConfig()

	<-ctx.Done()
}

// GetConfig returns the current configuration.
func (m *Manager) GetConfig() *Config {
	return m.Config
}
