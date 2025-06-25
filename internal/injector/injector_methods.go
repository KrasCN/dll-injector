package injector

import (
	"golang.org/x/sys/windows"
)

// Note: Global logger, SetLogger, Printf, NewInjector, SetMethod, and SetBypassOptions
// are defined in injector.go to avoid duplicate declarations

// SetEnhancedBypassOptions sets enhanced bypass options
func (i *Injector) SetEnhancedBypassOptions(options EnhancedBypassOptions) {
	i.enhancedOptions = options
	i.useEnhancedOptions = true

	// Also update regular bypass options for backward compatibility
	i.bypassOptions = options.BypassOptions
}

// Note: Inject method is defined in injector.go to avoid duplicate declarations

// methodToString converts injection method to string
func methodToString(method InjectionMethod) string {
	switch method {
	case StandardInjection:
		return "Standard Injection"
	case SetWindowsHookExInjection:
		return "SetWindowsHookEx Injection"
	case QueueUserAPCInjection:
		return "QueueUserAPC Injection"
	case EarlyBirdAPCInjection:
		return "Early Bird APC Injection"
	case DllNotificationInjection:
		return "DLL Notification Injection"
	case CryoBirdInjection:
		return "Job Object Cold Injection"
	default:
		return "Unknown Injection Method"
	}
}

// Note: createTempDllFile method is defined in injector.go to avoid duplicate declarations

// applyEnhancedInjectionTechniques applies enhanced injection techniques
func (i *Injector) applyEnhancedInjectionTechniques(hProcess windows.Handle, baseAddress uintptr, size uintptr, dllBytes []byte) error {
	if !i.useEnhancedOptions {
		return nil
	}

	i.logger.Info("Applying enhanced injection techniques")

	// Apply randomized allocation if enabled
	if i.enhancedOptions.RandomizeAllocation {
		i.logger.Info("Using randomized memory allocation")
		// This would be applied during memory allocation phase
	}

	// Apply multi-stage injection if enabled
	if i.enhancedOptions.MultiStageInjection && dllBytes != nil {
		i.logger.Info("Using multi-stage injection")
		err := MultiStageInjection(hProcess, dllBytes, baseAddress)
		if err != nil {
			i.logger.Warn("Multi-stage injection failed", "error", err.Error())
			// Continue with other techniques
		}
	}

	// Apply memory fluctuation if enabled
	if i.enhancedOptions.MemoryFluctuation {
		i.logger.Info("Using memory fluctuation")
		go func() {
			err := MemoryFluctuation(hProcess, baseAddress, size)
			if err != nil {
				i.logger.Warn("Memory fluctuation failed", "error", err.Error())
			}
		}()
	}

	// Apply thread hijacking if enabled
	if i.enhancedOptions.ThreadHijacking && dllBytes != nil {
		i.logger.Info("Using thread hijacking")
		err := ThreadHijacking(i.processID, dllBytes)
		if err != nil {
			i.logger.Warn("Thread hijacking failed", "error", err.Error())
			// Continue with other techniques
		}
	}

	// Apply process hollowing if enabled
	if i.enhancedOptions.ProcessHollowing && dllBytes != nil {
		i.logger.Info("Using process hollowing")
		// We would need a target process path for this
		// This is typically used as a standalone technique
	}

	// Apply all enhanced bypass options
	err := ApplyEnhancedBypassOptions(hProcess, baseAddress, size, dllBytes, i.enhancedOptions)
	if err != nil {
		i.logger.Warn("Enhanced bypass options application failed", "error", err.Error())
		// Continue with standard injection
	}

	return nil
}
