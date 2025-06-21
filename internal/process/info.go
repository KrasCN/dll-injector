package process

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

// ProcessEntry 表示一个进程条目
type ProcessEntry struct {
	PID        int32
	Name       string
	Executable string
}

// Info 管理进程信息
type Info struct {
	processes  []ProcessEntry
	mu         sync.RWMutex
	lastUpdate time.Time
}

// NewInfo 创建一个新的进程信息管理器
func NewInfo() *Info {
	info := &Info{}
	info.Refresh() // 初始加载进程列表
	return info
}

// Refresh 刷新进程列表
func (i *Info) Refresh() error {
	processes, err := process.Processes()
	if err != nil {
		return fmt.Errorf("获取进程列表失败: %v", err)
	}

	var entries []ProcessEntry

	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			// 如果无法获取名称，就跳过这个进程
			continue
		}

		exe, err := p.Exe()
		if err != nil {
			// 如果无法获取可执行文件路径，只使用名称
			exe = ""
		}

		entries = append(entries, ProcessEntry{
			PID:        p.Pid,
			Name:       name,
			Executable: exe,
		})
	}

	// 按名称排序进程
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

	// 返回进程列表的副本，以防在调用函数中修改
	result := make([]ProcessEntry, len(i.processes))
	copy(result, i.processes)

	return result
}

// GetProcessByName 根据进程名获取进程信息
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

// LastUpdateTime 返回最后更新时间
func (i *Info) LastUpdateTime() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.lastUpdate
}
