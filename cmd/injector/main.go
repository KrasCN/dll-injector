package main

import (
	"github.com/whispin/dll-injector/internal/ui"
	"go.uber.org/zap"
)

func main() {
	// Create new giu-based UI app
	app := ui.NewGuiApplication("DLL Injector", 1400, 900)

	// Log startup using app's logger (will show in UI)
	logger := app.Log()
	logger.Info("DLL Injector starting with new giu interface...")

	// Start the application
	if err := app.Run(); err != nil {
		logger.Error("Application runtime error", zap.Error(err))
	}

	logger.Info("DLL Injector shutting down...")
}
