package injector

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PE文件头结构
type PEHeader struct {
	NTHeader       ImageNtHeaders
	SectionHeaders []ImageSectionHeader
	OptionalHeader ImageOptionalHeader
}

// 自定义PE文件结构定义
type ImageDosHeader struct {
	Magic    uint16     // DOS signature: MZ
	Cblp     uint16     // Bytes on last page of file
	Cp       uint16     // Pages in file
	Crlc     uint16     // Relocations
	Cparhdr  uint16     // Size of header in paragraphs
	MinAlloc uint16     // Minimum extra paragraphs needed
	MaxAlloc uint16     // Maximum extra paragraphs needed
	Ss       uint16     // Initial (relative) SS value
	Sp       uint16     // Initial SP value
	Csum     uint16     // Checksum
	Ip       uint16     // Initial IP value
	Cs       uint16     // Initial (relative) CS value
	Lfarlc   uint16     // File address of relocation table
	Ovno     uint16     // Overlay number
	Res      [4]uint16  // Reserved words
	Oemid    uint16     // OEM identifier (for e_oeminfo)
	Oeminfo  uint16     // OEM information; e_oemid specific
	Res2     [10]uint16 // Reserved words
	Lfanew   uint32     // File address of new exe header
}

type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

type ImageOptionalHeader struct {
	Magic                       uint16
	MajorLinkerVersion          uint8
	MinorLinkerVersion          uint8
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // 32位特有，64位没有这个字段
	ImageBase                   uint64 // 在32位中是uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64 // 在32位中是uint32
	SizeOfStackCommit           uint64 // 在32位中是uint32
	SizeOfHeapReserve           uint64 // 在32位中是uint32
	SizeOfHeapCommit            uint64 // 在32位中是uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]ImageDataDirectory
}

type ImageNtHeaders struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader
}

type ImageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

type ImageImportDescriptor struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	Name               uint32
	FirstThunk         uint32
}

type ImageBaseRelocation struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

// ParsePEHeader parses PE file header
func ParsePEHeader(dllBytes []byte) (*PEHeader, error) {
	if len(dllBytes) < 64 {
		return nil, fmt.Errorf("DLL file is too small")
	}

	// 检查MZ签名
	if dllBytes[0] != 'M' || dllBytes[1] != 'Z' {
		return nil, fmt.Errorf("Invalid MZ signature")
	}

	// 获取PE头偏移
	peOffset := *(*uint32)(unsafe.Pointer(&dllBytes[0x3C]))
	if int(peOffset)+4 > len(dllBytes) {
		return nil, fmt.Errorf("Invalid PE offset")
	}

	// 检查PE签名
	if dllBytes[peOffset] != 'P' || dllBytes[peOffset+1] != 'E' || dllBytes[peOffset+2] != 0 || dllBytes[peOffset+3] != 0 {
		return nil, fmt.Errorf("Invalid PE signature")
	}

	// 解析NT头
	ntHeader := ImageNtHeaders{}
	ntHeaderSize := unsafe.Sizeof(ntHeader)
	if int(peOffset)+int(ntHeaderSize) > len(dllBytes) {
		return nil, fmt.Errorf("Invalid NT header")
	}

	// 复制NT头
	ntHeaderPtr := unsafe.Pointer(&dllBytes[peOffset])
	*(*ImageNtHeaders)(unsafe.Pointer(&ntHeader)) = *(*ImageNtHeaders)(ntHeaderPtr)

	// 解析可选头
	optionalHeader := ImageOptionalHeader{}
	optionalHeaderSize := unsafe.Sizeof(optionalHeader)
	optionalHeaderOffset := peOffset + 4 + 20 // PE签名(4) + 文件头(20)
	if int(optionalHeaderOffset)+int(optionalHeaderSize) > len(dllBytes) {
		return nil, fmt.Errorf("Invalid optional header")
	}

	// 复制可选头
	optionalHeaderPtr := unsafe.Pointer(&dllBytes[optionalHeaderOffset])
	*(*ImageOptionalHeader)(unsafe.Pointer(&optionalHeader)) = *(*ImageOptionalHeader)(optionalHeaderPtr)

	// 解析节表
	numSections := ntHeader.FileHeader.NumberOfSections
	sectionHeaderSize := unsafe.Sizeof(ImageSectionHeader{})
	sectionTableOffset := optionalHeaderOffset + uint32(ntHeader.FileHeader.SizeOfOptionalHeader)

	sectionHeaders := make([]ImageSectionHeader, numSections)
	for i := uint16(0); i < numSections; i++ {
		offset := sectionTableOffset + uint32(i)*uint32(sectionHeaderSize)
		if int(offset)+int(sectionHeaderSize) > len(dllBytes) {
			return nil, fmt.Errorf("Invalid section table")
		}

		sectionHeaderPtr := unsafe.Pointer(&dllBytes[offset])
		sectionHeaders[i] = *(*ImageSectionHeader)(sectionHeaderPtr)
	}

	return &PEHeader{
		NTHeader:       ntHeader,
		SectionHeaders: sectionHeaders,
		OptionalHeader: optionalHeader,
	}, nil
}

// MapSections maps PE file sections to remote process memory
func MapSections(hProcess windows.Handle, dllBytes []byte, baseAddress uintptr, peHeader *PEHeader) error {
	// 首先写入PE头
	headerSize := peHeader.OptionalHeader.SizeOfHeaders
	var bytesWritten uintptr
	err := WriteProcessMemory(hProcess, baseAddress, unsafe.Pointer(&dllBytes[0]), uintptr(headerSize), &bytesWritten)
	if err != nil {
		return fmt.Errorf("Failed to write PE header: %v", err)
	}

	// 写入各节
	for _, section := range peHeader.SectionHeaders {
		// 计算节在内存中的地址
		sectionAddress := baseAddress + uintptr(section.VirtualAddress)

		// 计算节在文件中的偏移和大小
		fileOffset := section.PointerToRawData
		fileSize := section.SizeOfRawData

		// 如果节在文件中有数据
		if fileOffset > 0 && fileSize > 0 {
			// 确保不超出文件边界
			if int(fileOffset)+int(fileSize) > len(dllBytes) {
				return fmt.Errorf("Section data exceeds file boundaries")
			}

			// 写入节数据
			err := WriteProcessMemory(hProcess, sectionAddress, unsafe.Pointer(&dllBytes[fileOffset]), uintptr(fileSize), &bytesWritten)
			if err != nil {
				return fmt.Errorf("Failed to write section data: %v", err)
			}
		}
	}

	return nil
}

// FixImports fixes import table
func FixImports(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	// 获取导入表目录
	importDir := peHeader.OptionalHeader.DataDirectory[1] // IMAGE_DIRECTORY_ENTRY_IMPORT = 1
	if importDir.Size == 0 {
		// 没有导入表
		return nil
	}

	// 导入表的RVA
	importTableRVA := importDir.VirtualAddress
	importTableAddr := baseAddress + uintptr(importTableRVA)

	// 读取导入表
	var importDesc ImageImportDescriptor
	var importDescSize = unsafe.Sizeof(importDesc)

	for i := uint32(0); ; i++ {
		// 计算当前导入描述符的地址
		currentImportDescAddr := importTableAddr + uintptr(i)*importDescSize

		// 读取导入描述符
		var bytesRead uintptr
		err := windows.ReadProcessMemory(hProcess, currentImportDescAddr, (*byte)(unsafe.Pointer(&importDesc)), importDescSize, &bytesRead)
		if err != nil {
			return fmt.Errorf("Failed to read import descriptor: %v", err)
		}

		// 如果全为0，说明已经到达导入表末尾
		if importDesc.Name == 0 && importDesc.FirstThunk == 0 {
			break
		}

		// 读取DLL名称
		dllNameAddr := baseAddress + uintptr(importDesc.Name)
		dllName := make([]byte, 256)
		err = windows.ReadProcessMemory(hProcess, dllNameAddr, &dllName[0], 256, &bytesRead)
		if err != nil {
			return fmt.Errorf("Failed to read DLL name: %v", err)
		}

		// 找到字符串结束符
		var dllNameLen int
		for i := 0; i < 256; i++ {
			if dllName[i] == 0 {
				dllNameLen = i
				break
			}
		}
		dllNameStr := string(dllName[:dllNameLen])

		// 加载DLL
		hModule, err := windows.LoadLibrary(dllNameStr)
		if err != nil {
			return fmt.Errorf("Failed to load DLL %s: %v", dllNameStr, err)
		}
		defer windows.FreeLibrary(hModule)

		// 处理导入函数
		var thunk uint32
		if importDesc.OriginalFirstThunk != 0 {
			thunk = importDesc.OriginalFirstThunk
		} else {
			thunk = importDesc.FirstThunk
		}

		// 遍历每个导入函数
		// 确定指针大小（32位或64位）
		var ptrSize uintptr
		if unsafe.Sizeof(uintptr(0)) == 8 {
			ptrSize = 8 // 64位
		} else {
			ptrSize = 4 // 32位
		}

		for j := uint32(0); ; j++ {
			// 计算当前Thunk的地址
			thunkAddr := baseAddress + uintptr(thunk) + uintptr(j)*ptrSize
			var thunkData uint64

			// 根据架构读取不同大小的数据
			if ptrSize == 8 {
				err := windows.ReadProcessMemory(hProcess, thunkAddr, (*byte)(unsafe.Pointer(&thunkData)), 8, &bytesRead)
				if err != nil {
					return fmt.Errorf("Failed to read thunk data: %v", err)
				}
			} else {
				var thunkData32 uint32
				err := windows.ReadProcessMemory(hProcess, thunkAddr, (*byte)(unsafe.Pointer(&thunkData32)), 4, &bytesRead)
				if err != nil {
					return fmt.Errorf("Failed to read thunk data: %v", err)
				}
				thunkData = uint64(thunkData32)
			}

			// 如果Thunk为0，说明已经到达导入函数列表末尾
			if thunkData == 0 {
				break
			}

			// 计算IAT条目的地址
			iatEntryAddr := baseAddress + uintptr(importDesc.FirstThunk) + uintptr(j)*ptrSize

			// 判断是按名称导入还是按序号导入
			var procAddr uintptr
			isOrdinal := (thunkData & getOrdinalMask()) != 0

			if isOrdinal {
				// 按序号导入
				ordinal := uint16(thunkData & 0xFFFF)
				// 使用GetProcAddress的序号版本
				kernel32 := windows.NewLazySystemDLL("kernel32.dll")
				getProcAddress := kernel32.NewProc("GetProcAddress")
				r1, _, err := getProcAddress.Call(uintptr(hModule), uintptr(ordinal))
				if r1 == 0 {
					return fmt.Errorf("Failed to get function address by ordinal %d: %v", ordinal, err)
				}
				procAddr = uintptr(r1)
			} else {
				// 按名称导入
				// 读取导入函数名称
				var nameRVA uint64
				if ptrSize == 8 {
					nameRVA = thunkData & 0x7FFFFFFFFFFFFFFF
				} else {
					nameRVA = thunkData & 0x7FFFFFFF
				}

				nameAddr := baseAddress + uintptr(nameRVA) + 2 // +2跳过Hint
				funcName := make([]byte, 256)
				err := windows.ReadProcessMemory(hProcess, nameAddr, &funcName[0], 256, &bytesRead)
				if err != nil {
					return fmt.Errorf("Failed to read function name: %v", err)
				}

				// 找到字符串结束符
				var funcNameLen int
				for i := 0; i < 256; i++ {
					if funcName[i] == 0 {
						funcNameLen = i
						break
					}
				}
				funcNameStr := string(funcName[:funcNameLen])

				// 获取函数地址
				procAddr, err = windows.GetProcAddress(hModule, funcNameStr)
				if err != nil {
					return fmt.Errorf("Failed to get function address for %s: %v", funcNameStr, err)
				}
			}

			// 写入函数地址到IAT
			var bytesWritten uintptr
			err = WriteProcessMemory(hProcess, iatEntryAddr, unsafe.Pointer(&procAddr), ptrSize, &bytesWritten)
			if err != nil {
				return fmt.Errorf("Failed to write function address to IAT: %v", err)
			}
		}
	}

	return nil
}

// FixRelocations fixes relocations
func FixRelocations(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	// 获取重定位表目录
	relocDir := peHeader.OptionalHeader.DataDirectory[5] // IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
	if relocDir.Size == 0 {
		// 没有重定位表
		return nil
	}

	// 计算基址差值
	delta := int64(baseAddress) - int64(peHeader.OptionalHeader.ImageBase)
	if delta == 0 {
		// 如果基址没变，不需要修复
		return nil
	}

	// 重定位表的RVA
	relocTableRVA := relocDir.VirtualAddress
	relocTableAddr := baseAddress + uintptr(relocTableRVA)

	// 读取重定位块
	var relocBlock ImageBaseRelocation
	var relocBlockSize = unsafe.Sizeof(relocBlock)
	var bytesRead uintptr

	// 遍历所有重定位块
	offset := uint32(0)
	for offset < relocDir.Size {
		// 读取重定位块头
		err := windows.ReadProcessMemory(hProcess, relocTableAddr+uintptr(offset), (*byte)(unsafe.Pointer(&relocBlock)), relocBlockSize, &bytesRead)
		if err != nil {
			return fmt.Errorf("读取重定位块失败: %v", err)
		}

		// 如果VirtualAddress为0，表示结束
		if relocBlock.VirtualAddress == 0 {
			break
		}

		// 计算条目数量
		numEntries := (relocBlock.SizeOfBlock - 8) / 2 // 每个条目2字节

		// 读取所有条目
		entries := make([]uint16, numEntries)
		entriesAddr := relocTableAddr + uintptr(offset) + relocBlockSize
		err = windows.ReadProcessMemory(hProcess, entriesAddr, (*byte)(unsafe.Pointer(&entries[0])), uintptr(numEntries*2), &bytesRead)
		if err != nil {
			return fmt.Errorf("读取重定位条目失败: %v", err)
		}

		// 处理每个条目
		for _, entry := range entries {
			// 高4位是类型，低12位是偏移
			relocType := entry >> 12
			relocOffset := entry & 0xFFF

			// 只处理IMAGE_REL_BASED_HIGHLOW (3) 和 IMAGE_REL_BASED_DIR64 (10)
			if relocType == 3 || relocType == 10 {
				// 计算需要修复的地址
				fixAddr := baseAddress + uintptr(relocBlock.VirtualAddress) + uintptr(relocOffset)

				// 读取当前值
				var value uint64
				valueSize := uintptr(4)
				if relocType == 10 {
					valueSize = 8
				}

				err := windows.ReadProcessMemory(hProcess, fixAddr, (*byte)(unsafe.Pointer(&value)), valueSize, &bytesRead)
				if err != nil {
					return fmt.Errorf("读取重定位值失败: %v", err)
				}

				// 修正值
				value = uint64(int64(value) + delta)

				// 写回修正后的值
				err = windows.WriteProcessMemory(hProcess, fixAddr, (*byte)(unsafe.Pointer(&value)), valueSize, &bytesRead)
				if err != nil {
					return fmt.Errorf("写入重定位值失败: %v", err)
				}
			}
		}

		// 移动到下一个块
		offset += relocBlock.SizeOfBlock
	}

	return nil
}

// ExecuteDllEntry 执行DLL入口点
func ExecuteDllEntry(hProcess windows.Handle, baseAddress uintptr, peHeader *PEHeader) error {
	// 获取入口点RVA
	entryPointRVA := peHeader.OptionalHeader.AddressOfEntryPoint
	if entryPointRVA == 0 {
		// 没有入口点
		return nil
	}

	// 计算入口点地址
	entryPointAddr := baseAddress + uintptr(entryPointRVA)

	// 创建远程线程执行入口点
	var threadID uint32
	threadHandle, err := CreateRemoteThread(hProcess, nil, 0, entryPointAddr, baseAddress, 0, &threadID)
	if err != nil {
		return fmt.Errorf("创建远程线程执行入口点失败: %v", err)
	}
	defer windows.CloseHandle(threadHandle)

	// 等待线程结束
	windows.WaitForSingleObject(threadHandle, windows.INFINITE)

	return nil
}
