package injector

import (
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// diskLoadDLLWithSpoofing loads DLL from disk with path spoofing
func (i *Injector) diskLoadDLLWithSpoofing() error {
	i.logger.Info("Using path spoofing method")

	// 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		errMsg := "Failed to open target process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	i.logger.Info("Successfully opened target process")

	// 创建欺骗性路径
	// 使用Windows系统DLL路径作为伪装
	systemDir, err := windows.GetSystemDirectory()
	if err != nil {
		i.logger.Warn("Failed to get system directory, using C:\\Windows\\System32", "error", err)
		systemDir = "C:\\Windows\\System32"
	}

	// 创建伪装路径 - 使用系统DLL名称
	spoofedNames := []string{
		"kernel32.dll",
		"user32.dll",
		"advapi32.dll",
		"gdi32.dll",
		"shell32.dll",
	}

	// 选择一个系统DLL名称
	spoofedName := spoofedNames[0]
	spoofedPath := filepath.Join(systemDir, spoofedName)

	i.logger.Info("Using spoofed path",
		"original_path", i.dllPath,
		"spoofed_path", spoofedPath)

	// 复制原始DLL到临时位置
	tempDir := os.TempDir()
	tempFile := filepath.Join(tempDir, spoofedName)

	// 读取原始DLL
	dllData, err := os.ReadFile(i.dllPath)
	if err != nil {
		errMsg := "Failed to read original DLL: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}

	// 写入临时文件
	err = os.WriteFile(tempFile, dllData, 0644)
	if err != nil {
		errMsg := "Failed to write temporary DLL: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}

	// 确保函数退出时删除临时文件
	defer os.Remove(tempFile)

	// 将伪装路径写入目标进程
	spoofedPathBytes := []byte(spoofedPath + "\x00")

	// 分配内存
	var memFlags uint32 = windows.MEM_RESERVE | windows.MEM_COMMIT
	var memProt uint32 = windows.PAGE_READWRITE

	pathAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(spoofedPathBytes)),
		memFlags, memProt)
	if err != nil {
		errMsg := "Failed to allocate memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}

	// 写入伪装路径
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&spoofedPathBytes[0]),
		uintptr(len(spoofedPathBytes)), &bytesWritten)
	if err != nil {
		errMsg := "Failed to write to memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// 创建远程线程
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		loadLibraryAddr, pathAddr, 0, &threadID)
	if err != nil {
		errMsg := "Failed to create remote thread: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Path spoofing failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Successfully created remote thread with spoofed path", "thread_id", threadID)

	return nil
}
