// Package logger provides a structured logger for the Chameleon protocol.
package logger

import (
	"log/slog"
	"os"
	"strings"
)

// New creates a slog.Logger with the specified level.
func New(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn", "warning":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	handler := slog.NewTextHandler(os.Stderr, opts)
	return slog.New(handler)
}
