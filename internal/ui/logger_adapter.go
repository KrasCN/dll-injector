package ui

import (
	"go.uber.org/zap"
)

// LoggerAdapter adapts zap.Logger to the interface expected by the injector package
type LoggerAdapter struct {
	logger *zap.Logger
}

// NewLoggerAdapter creates a new logger adapter
func NewLoggerAdapter(logger *zap.Logger) *LoggerAdapter {
	return &LoggerAdapter{logger: logger}
}

// Info logs an info message
func (l *LoggerAdapter) Info(msg string, fields ...interface{}) {
	if len(fields) == 0 {
		l.logger.Info(msg)
		return
	}

	// Convert fields to zap fields
	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			zapFields = append(zapFields, zap.Any(key, fields[i+1]))
		}
	}
	l.logger.Info(msg, zapFields...)
}

// Error logs an error message
func (l *LoggerAdapter) Error(msg string, fields ...interface{}) {
	if len(fields) == 0 {
		l.logger.Error(msg)
		return
	}

	// Convert fields to zap fields
	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			zapFields = append(zapFields, zap.Any(key, fields[i+1]))
		}
	}
	l.logger.Error(msg, zapFields...)
}

// Warn logs a warning message
func (l *LoggerAdapter) Warn(msg string, fields ...interface{}) {
	if len(fields) == 0 {
		l.logger.Warn(msg)
		return
	}

	// Convert fields to zap fields
	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			zapFields = append(zapFields, zap.Any(key, fields[i+1]))
		}
	}
	l.logger.Warn(msg, zapFields...)
}

// Debug logs a debug message
func (l *LoggerAdapter) Debug(msg string, fields ...interface{}) {
	if len(fields) == 0 {
		l.logger.Debug(msg)
		return
	}

	// Convert fields to zap fields
	zapFields := make([]zap.Field, 0, len(fields)/2)
	for i := 0; i < len(fields)-1; i += 2 {
		if key, ok := fields[i].(string); ok {
			zapFields = append(zapFields, zap.Any(key, fields[i+1]))
		}
	}
	l.logger.Debug(msg, zapFields...)
}
