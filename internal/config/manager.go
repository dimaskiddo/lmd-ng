package config

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	"github.com/dimaskiddo/lmd-ng/internal/log"
)

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

	// Set default values directly on the Config struct
	SetDefaultConfig(m.Config)

	// Configure Viper to read from the specified path or default locations
	if configFilePath != "" {
		m.Viper.SetConfigFile(configFilePath)
	} else {
		m.Viper.SetConfigName("config")
		m.Viper.SetConfigType("yaml")

		m.Viper.AddConfigPath(".")
		m.Viper.AddConfigPath("/etc/lmd-ng/")
		m.Viper.AddConfigPath("/usr/local/etc/lmd-ng/")
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

	// Resolve absolute paths for application directories
	m.Config.App.BasePath, _ = filepath.Abs(m.Config.App.BasePath)

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

		// Resolve absolute paths for application directories again
		m.Config.App.BasePath, _ = filepath.Abs(m.Config.App.BasePath)

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
