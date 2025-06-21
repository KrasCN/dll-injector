package memory

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unsafe"
)

// PEFile 表示一个PE文件
type PEFile struct {
	data          []byte
	dosHeader     *ImageDOSHeader
	ntHeaders     *ImageNTHeaders
	sectionHeader []*ImageSectionHeader
	exportDir     *ImageExportDirectory
}

// ImageDOSHeader DOS头结构
type ImageDOSHeader struct {
	Magic    uint16     // DOS .EXE 魔数
	Cblp     uint16     // 最后页的字节数
	Cp       uint16     // 文件中的页数
	Crlc     uint16     // 重定位表项数
	Cparhdr  uint16     // 头部尺寸，以段落为单位
	MinAlloc uint16     // 所需的最小附加段
	MaxAlloc uint16     // 所需的最大附加段
	SS       uint16     // 初始的SS值
	SP       uint16     // 初始的SP值
	CSum     uint16     // 校验和
	IP       uint16     // 初始的IP值
	CS       uint16     // 初始的CS值
	LfaRlc   uint16     // 重定位表的文件地址
	Ovno     uint16     // 覆盖号
	Res      [4]uint16  // 保留字
	OEMID    uint16     // OEM标识符
	OEMInfo  uint16     // OEM信息
	Res2     [10]uint16 // 保留字
	LfaNew   int32      // PE头的文件地址
}

// ImageFileHeader PE文件头
type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// ImageDataDirectory 数据目录
type ImageDataDirectory struct {
	VirtualAddress uint32
	Size           uint32
}

// ImageOptionalHeader PE可选头
type ImageOptionalHeader struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	BaseOfData                  uint32 // 只在PE32中存在
	ImageBase                   uint64
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
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               [16]ImageDataDirectory
}

// ImageNTHeaders NT头
type ImageNTHeaders struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader ImageOptionalHeader
}

// ImageSectionHeader 节头
type ImageSectionHeader struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

// ImageExportDirectory 导出目录
type ImageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

// Constants
const (
	IMAGE_DOS_SIGNATURE          = 0x5A4D // MZ
	IMAGE_NT_SIGNATURE           = 0x00004550
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
	IMAGE_SCN_MEM_EXECUTE        = 0x20000000
	IMAGE_SCN_MEM_READ           = 0x40000000
	IMAGE_SCN_MEM_WRITE          = 0x80000000
)

// NewPEFile 从字节数组创建PE文件
func NewPEFile(data []byte) (*PEFile, error) {
	if len(data) < int(unsafe.Sizeof(ImageDOSHeader{})) {
		return nil, errors.New("文件太小，不是有效的PE文件")
	}

	pe := &PEFile{
		data: data,
	}

	// 读取DOS头
	r := bytes.NewReader(data)
	pe.dosHeader = &ImageDOSHeader{}
	if err := binary.Read(r, binary.LittleEndian, pe.dosHeader); err != nil {
		return nil, err
	}

	// 验证DOS魔数
	if pe.dosHeader.Magic != IMAGE_DOS_SIGNATURE {
		return nil, errors.New("无效的DOS签名")
	}

	// 读取NT头
	if _, err := r.Seek(int64(pe.dosHeader.LfaNew), io.SeekStart); err != nil {
		return nil, err
	}

	pe.ntHeaders = &ImageNTHeaders{}
	if err := binary.Read(r, binary.LittleEndian, &pe.ntHeaders.Signature); err != nil {
		return nil, err
	}

	// 验证NT魔数
	if pe.ntHeaders.Signature != IMAGE_NT_SIGNATURE {
		return nil, errors.New("无效的NT签名")
	}

	// 读取文件头
	if err := binary.Read(r, binary.LittleEndian, &pe.ntHeaders.FileHeader); err != nil {
		return nil, err
	}

	// 读取可选头
	if err := binary.Read(r, binary.LittleEndian, &pe.ntHeaders.OptionalHeader); err != nil {
		return nil, err
	}

	// 读取节头
	pe.sectionHeader = make([]*ImageSectionHeader, pe.ntHeaders.FileHeader.NumberOfSections)
	for i := range pe.sectionHeader {
		pe.sectionHeader[i] = &ImageSectionHeader{}
		if err := binary.Read(r, binary.LittleEndian, pe.sectionHeader[i]); err != nil {
			return nil, err
		}
	}

	// 读取导出目录
	if pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0 {
		exportRVA := pe.ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
		exportOffset, err := pe.RVAToOffset(exportRVA)
		if err != nil {
			return nil, err
		}

		if exportOffset+uint32(unsafe.Sizeof(ImageExportDirectory{})) > uint32(len(data)) {
			return nil, errors.New("导出目录超出文件范围")
		}

		exportData := data[exportOffset : exportOffset+uint32(unsafe.Sizeof(ImageExportDirectory{}))]
		exportReader := bytes.NewReader(exportData)
		pe.exportDir = &ImageExportDirectory{}
		if err := binary.Read(exportReader, binary.LittleEndian, pe.exportDir); err != nil {
			return nil, err
		}
	}

	return pe, nil
}

// GetEntryPoint 获取入口点RVA
func (pe *PEFile) GetEntryPoint() uint32 {
	return pe.ntHeaders.OptionalHeader.AddressOfEntryPoint
}

// GetImageBase 获取映像基址
func (pe *PEFile) GetImageBase() uint64 {
	return pe.ntHeaders.OptionalHeader.ImageBase
}

// GetSectionByRVA 根据RVA获取所在节
func (pe *PEFile) GetSectionByRVA(rva uint32) (*ImageSectionHeader, error) {
	for _, section := range pe.sectionHeader {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.VirtualSize {
			return section, nil
		}
	}
	return nil, fmt.Errorf("找不到包含RVA 0x%X的节", rva)
}

// RVAToOffset 将RVA转换为文件偏移
func (pe *PEFile) RVAToOffset(rva uint32) (uint32, error) {
	section, err := pe.GetSectionByRVA(rva)
	if err != nil {
		return 0, err
	}

	offset := rva - section.VirtualAddress + section.PointerToRawData
	return offset, nil
}

// OffsetToRVA 将文件偏移转换为RVA
func (pe *PEFile) OffsetToRVA(offset uint32) (uint32, error) {
	for _, section := range pe.sectionHeader {
		if offset >= section.PointerToRawData && offset < section.PointerToRawData+section.SizeOfRawData {
			rva := offset - section.PointerToRawData + section.VirtualAddress
			return rva, nil
		}
	}
	return 0, fmt.Errorf("找不到包含偏移 0x%X的节", offset)
}

// ErasePEHeader 擦除PE头
func (pe *PEFile) ErasePEHeader() {
	// 擦除DOS头
	for i := range pe.data[:len(pe.data)] {
		if i >= int(pe.ntHeaders.OptionalHeader.SizeOfHeaders) {
			break
		}
		pe.data[i] = 0
	}
}

// EraseEntryPoint 擦除入口点
func (pe *PEFile) EraseEntryPoint() error {
	entryRVA := pe.GetEntryPoint()
	if entryRVA == 0 {
		return errors.New("PE文件没有入口点")
	}

	offset, err := pe.RVAToOffset(entryRVA)
	if err != nil {
		return err
	}

	// 简单地将入口点的代码替换为返回指令
	if offset < uint32(len(pe.data)) {
		pe.data[offset] = 0xC3 // x86/x64 RET指令
	}

	return nil
}

// SectionNameString 获取节的名称
func (s *ImageSectionHeader) SectionNameString() string {
	end := 0
	for i, b := range s.Name {
		if b == 0 {
			end = i
			break
		}
		end = len(s.Name)
	}
	return string(s.Name[:end])
}
