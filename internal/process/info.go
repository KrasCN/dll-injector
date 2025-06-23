package process

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// ProcessEntry represents a process entry
type ProcessEntry struct {
	PID        int32
	Name       string
	Executable string
}

// Info manages process information
type Info struct {
	processes  []ProcessEntry
	mu         sync.RWMutex
	lastUpdate time.Time
}

// NewInfo creates a new process information manager
func NewInfo() *Info {
	info := &Info{}
	info.Refresh() // Initial loading of process list
	return info
}

// Refresh refreshes the process list
func (i *Info) Refresh() error {
	processes, err := process.Processes()
	if err != nil {
		return fmt.Errorf("Failed to get process list: %v", err)
	}

	var entries []ProcessEntry

	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			// If unable to get name, skip this process
			continue
		}

		exe, err := p.Exe()
		if err != nil {
			// If unable to get executable path, use name only
			exe = ""
		}

		entries = append(entries, ProcessEntry{
			PID:        p.Pid,
			Name:       name,
			Executable: exe,
		})
	}

	// Sort processes by name
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	i.mu.Lock()
	i.processes = entries
	i.lastUpdate = time.Now()
	i.mu.Unlock()

	return nil
}

// GetProcesses 返回当前进程列表
func (i *Info) GetProcesses() []ProcessEntry {
	i.mu.RLock()
	defer i.mu.RUnlock()

	// Return a copy of the process list to prevent modification in calling function
	result := make([]ProcessEntry, len(i.processes))
	copy(result, i.processes)

	return result
}

// GetProcessByName gets process information by process name
func (i *Info) GetProcessByName(name string) ([]ProcessEntry, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()

	var result []ProcessEntry

	for _, p := range i.processes {
		if p.Name == name {
			result = append(result, p)
		}
	}

	return result, len(result) > 0
}

// LastUpdateTime returns the last update time
func (i *Info) LastUpdateTime() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.lastUpdate
}
