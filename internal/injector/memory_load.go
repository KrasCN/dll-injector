package injector

import (
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

// memoryLoadDLL loads DLL from memory
func (i *Injector) memoryLoadDLL(dllBytes []byte) error {
	i.logger.Info("Using memory load method")

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
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	i.logger.Info("Successfully opened target process")

	// 分配内存
	dllSize := len(dllBytes)
	var memAddr uintptr
	var memFlags uint32 = windows.MEM_RESERVE | windows.MEM_COMMIT
	var memProt uint32 = windows.PAGE_READWRITE

	memAddr, err = VirtualAllocEx(hProcess, 0, uintptr(dllSize),
		memFlags, memProt)
	if err != nil {
		errMsg := "Failed to allocate memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 写入DLL数据
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllBytes[0]),
		uintptr(dllSize), &bytesWritten)
	if err != nil {
		errMsg := "Failed to write to memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr := loadLibraryA.Addr()

	// 创建远程线程
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		loadLibraryAddr, memAddr, 0, &threadID)
	if err != nil {
		errMsg := "Failed to create remote thread: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Successfully created remote thread", "thread_id", threadID)

	// 应用反检测技术
	if i.bypassOptions.ErasePEHeader {
		i.logger.Info("Erasing PE header for stealth")
		err = ErasePEHeader(hProcess, memAddr)
		if err != nil {
			i.logger.Warn("Failed to erase PE header", "error", err)
			// 不返回错误，因为这不是关键操作
		}
	}

	if i.bypassOptions.EraseEntryPoint {
		i.logger.Info("Erasing entry point for stealth")
		err = EraseEntryPoint(hProcess, memAddr)
		if err != nil {
			i.logger.Warn("Failed to erase entry point", "error", err)
			// 不返回错误，因为这不是关键操作
		}
	}

	// 应用高级反检测技术
	err = ApplyAdvancedBypassOptions(hProcess, memAddr, uintptr(dllSize), i.bypassOptions)
	if err != nil {
		i.logger.Warn("Failed to apply advanced bypass options", "error", err)
		// 不返回错误，因为这不是关键操作
	}

	return nil
}

// Note: manualMapDLL and legitProcessInject methods are defined in injector.go to avoid duplicate declarations
