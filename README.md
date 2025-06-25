# DLL Injector

An advanced DLL injection tool developed in Go with Fyne, designed for the Windows platform, offering multiple injection methods and sophisticated anti-detection features.

## Screenshot

![DLL Injector UI](https://github.com/whispin/dll-injector/blob/main/screenshot/main-ui.jpg?raw=true)

## Features

### Injection Methods
- Standard CreateRemoteThread injection
- SetWindowsHookEx injection
- QueueUserAPC injection
- Early Bird APC injection
- DLL notification injection
- Job Object freeze process injection

### Anti-Detection Techniques
- **Basic Techniques**
  - Load DLL from memory
  - PE header erasure
  - Entry point erasure
  - Manual mapping
  - Path spoofing

- **Advanced Techniques**
  - PTE modification
  - VAD manipulation
  - VAD node removal
  - Thread stack allocation
  - Direct system calls

### Additional Features
- Modern GUI interface using the giu framework (Dear ImGui for Go)
- Display of all system processes with search and filter functionality
- Real-time injection status and logging
- Interactive menu system with About dialog and GitHub integration
- Responsive and intuitive user interface

## System Requirements

- Windows operating system
- Go 1.24+

## Build Instructions

1. Ensure Go 1.24 or higher is installed
2. Clone the repository
3. Get dependencies: `go mod tidy`
4. Build the project: `go build -ldflags="-s -w -H windowsgui" -o dll-injector.exe ./cmd/injector`

## Usage

1. Run `dll-injector.exe`
2. Select the DLL file to inject
3. Choose the target process
4. Select injection method and anti-detection options
5. Click the "Inject" button to perform the injection

## Important Notes

- This tool is intended for educational and research purposes only
- Do not perform DLL injection on any software without proper authorization

## Code Structure

- `cmd/injector`: Main program entry point
- `internal/ui`: giu-based interface implementation
- `internal/process`: Process management functionality
- `internal/injector`: Core DLL injection functionality

## License

MIT 