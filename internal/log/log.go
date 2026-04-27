package log

import (
	"io"
	"log/slog"
	"os"

	"github.com/natefinch/lumberjack"
)

// Config holds the logging configuration.
type Config struct {
	Level      string
	Output     string
	FilePath   string
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Compress   bool
}

var logger *slog.Logger = slog.Default()

// InitLogger initializes the structured logger with rotation.
func InitLogger(cfg *Config) {
	var logWriter io.Writer

	if cfg.Output == "file" && cfg.FilePath != "" {
		lumberjackLogger := &lumberjack.Logger{
			Filename:   cfg.FilePath,
			MaxSize:    cfg.MaxSize,
			MaxBackups: cfg.MaxBackups,
			MaxAge:     cfg.MaxAge,
			Compress:   cfg.Compress,
		}
		logWriter = io.MultiWriter(os.Stdout, lumberjackLogger) // Log to stdout and file
	} else {
		logWriter = os.Stdout
	}

	var level slog.Level
	switch cfg.Level {
	case "debug":
		level = slog.LevelDebug

	case "info":
		level = slog.LevelInfo

	case "warn":
		level = slog.LevelWarn

	case "error":
		level = slog.LevelError

	default:
		level = slog.LevelInfo
	}

	handlerOptions := &slog.HandlerOptions{
		Level: level,
	}

	handler := slog.NewTextHandler(logWriter, handlerOptions)
	logger = slog.New(handler)

	slog.SetDefault(logger)
}

// GetLogger returns the initialized slog logger.
func GetLogger() *slog.Logger {
	return logger
}

// Debug logs a debug message.
func Debug(msg string, args ...any) {
	logger.Debug(msg, args...)
}

// Info logs an info message.
func Info(msg string, args ...any) {
	logger.Info(msg, args...)
}

// Warn logs a warning message.
func Warn(msg string, args ...any) {
	logger.Warn(msg, args...)
}

// Error logs an error message.
func Error(msg string, args ...any) {
	logger.Error(msg, args...)
}

// Fatal logs a fatal message and exits.
func Fatal(msg string, args ...any) {
	logger.Error(msg, args...)
	os.Exit(1)
}
