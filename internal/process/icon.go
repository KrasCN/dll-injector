package process

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
	"golang.org/x/sys/windows"
)

var (
	// 图标缓存
	iconCache     = make(map[string]fyne.Resource)
	iconCacheLock sync.RWMutex

	// Windows API
	shell32                    = windows.NewLazyDLL("shell32.dll")
	user32                     = windows.NewLazyDLL("user32.dll")
	gdi32                      = windows.NewLazyDLL("gdi32.dll")
	procSHGetFileInfo          = shell32.NewProc("SHGetFileInfoW")
	procDrawIconEx             = user32.NewProc("DrawIconEx")
	procGetDC                  = user32.NewProc("GetDC")
	procReleaseDC              = user32.NewProc("ReleaseDC")
	procCreateCompatibleDC     = gdi32.NewProc("CreateCompatibleDC")
	procDeleteDC               = gdi32.NewProc("DeleteDC")
	procCreateCompatibleBitmap = gdi32.NewProc("CreateCompatibleBitmap")
	procSelectObject           = gdi32.NewProc("SelectObject")
	procDeleteObject           = gdi32.NewProc("DeleteObject")
	procGetDIBits              = gdi32.NewProc("GetDIBits")
	procDestroyIcon            = user32.NewProc("DestroyIcon")
	procGetStockObject         = gdi32.NewProc("GetStockObject")
	procCreateSolidBrush       = gdi32.NewProc("CreateSolidBrush")
	procFillRect               = user32.NewProc("FillRect")

	// 常量
	DI_NORMAL       = 3
	WHITE_BRUSH     = 0
	SRCCOPY         = 0xCC0020
	DIB_RGB_COLORS  = 0
	BI_RGB          = 0
	SHGFI_ICON      = 0x000000100
	SHGFI_SMALLICON = 0x000000001
)

// SHFILEINFO 结构体
type SHFILEINFO struct {
	HIcon         windows.Handle
	IIcon         int32
	DwAttributes  uint32
	SzDisplayName [260]uint16
	SzTypeName    [80]uint16
}

// RECT 结构体
type RECT struct {
	Left   int32
	Top    int32
	Right  int32
	Bottom int32
}

// BITMAPINFOHEADER 结构体
type BITMAPINFOHEADER struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

// BITMAPINFO 结构体
type BITMAPINFO struct {
	BmiHeader BITMAPINFOHEADER
	BmiColors [1]RGBQUAD
}

// RGBQUAD 结构体
type RGBQUAD struct {
	RgbBlue     byte
	RgbGreen    byte
	RgbRed      byte
	RgbReserved byte
}

// 提取真实的Windows可执行文件图标
func extractWindowsIcon(filePath string) (image.Image, error) {
	// 检查文件存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, err
	}

	// 转换路径为UTF16字符串
	pathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return nil, err
	}

	// 准备SHFILEINFO结构体
	var shfi SHFILEINFO

	// 调用SHGetFileInfo获取图标
	ret, _, _ := procSHGetFileInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(unsafe.Pointer(&shfi)),
		uintptr(unsafe.Sizeof(shfi)),
		uintptr(SHGFI_ICON|SHGFI_SMALLICON),
	)

	if ret == 0 || shfi.HIcon == 0 {
		return nil, nil
	}
	defer procDestroyIcon.Call(uintptr(shfi.HIcon))

	// 获取DC
	hdc, _, _ := procGetDC.Call(0)
	if hdc == 0 {
		return nil, nil
	}
	defer procReleaseDC.Call(0, hdc)

	// 创建内存DC
	hdcMem, _, _ := procCreateCompatibleDC.Call(hdc)
	if hdcMem == 0 {
		return nil, nil
	}
	defer procDeleteDC.Call(hdcMem)

	// 图标大小
	iconSize := 16

	// 创建兼容位图
	hBitmap, _, _ := procCreateCompatibleBitmap.Call(
		hdc,
		uintptr(iconSize),
		uintptr(iconSize),
	)
	if hBitmap == 0 {
		return nil, nil
	}
	defer procDeleteObject.Call(hBitmap)

	// 选择位图到内存DC
	oldBitmap, _, _ := procSelectObject.Call(hdcMem, hBitmap)
	defer procSelectObject.Call(hdcMem, oldBitmap)

	// 创建白色背景刷子
	hBrush, _, _ := procGetStockObject.Call(uintptr(WHITE_BRUSH))

	// 填充白色背景
	rect := RECT{
		Left:   0,
		Top:    0,
		Right:  int32(iconSize),
		Bottom: int32(iconSize),
	}
	procFillRect.Call(
		hdcMem,
		uintptr(unsafe.Pointer(&rect)),
		hBrush,
	)

	// 绘制图标
	procDrawIconEx.Call(
		hdcMem,
		0, 0,
		uintptr(shfi.HIcon),
		uintptr(iconSize), uintptr(iconSize),
		0,
		0,
		uintptr(DI_NORMAL),
	)

	// 创建Go图像
	img := image.NewRGBA(image.Rect(0, 0, iconSize, iconSize))

	// 设置BITMAPINFO
	bmi := BITMAPINFO{}
	bmi.BmiHeader.BiSize = uint32(unsafe.Sizeof(bmi.BmiHeader))
	bmi.BmiHeader.BiWidth = int32(iconSize)
	bmi.BmiHeader.BiHeight = -int32(iconSize) // 负高度表示自上而下的DIB
	bmi.BmiHeader.BiPlanes = 1
	bmi.BmiHeader.BiBitCount = 32
	bmi.BmiHeader.BiCompression = uint32(BI_RGB)

	// 获取位图数据
	procGetDIBits.Call(
		hdcMem,
		hBitmap,
		0,
		uintptr(iconSize),
		uintptr(unsafe.Pointer(&img.Pix[0])),
		uintptr(unsafe.Pointer(&bmi)),
		uintptr(DIB_RGB_COLORS),
	)

	// Windows DIB的颜色顺序是BGRA，而Go的image.RGBA是RGBA
	// 需要交换R和B通道
	for y := 0; y < iconSize; y++ {
		for x := 0; x < iconSize; x++ {
			i := y*img.Stride + x*4
			img.Pix[i], img.Pix[i+2] = img.Pix[i+2], img.Pix[i] // 交换B和R
		}
	}

	return img, nil
}

// GetProcessIconResource 为进程获取图标
func GetProcessIconResource(proc ProcessEntry) fyne.Resource {
	exePath := proc.Executable
	if exePath == "" {
		return theme.ComputerIcon()
	}

	// 检查缓存
	iconCacheLock.RLock()
	if icon, ok := iconCache[exePath]; ok {
		iconCacheLock.RUnlock()
		return icon
	}
	iconCacheLock.RUnlock()

	// 尝试提取真实图标
	var icon fyne.Resource

	// 尝试提取Windows图标
	img, err := extractWindowsIcon(exePath)
	if err == nil && img != nil {
		// 将图像转换为PNG数据
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err == nil {
			// 创建Fyne资源
			icon = fyne.NewStaticResource(
				filepath.Base(exePath)+".png",
				buf.Bytes(),
			)
		}
	}

	// 如果无法提取图标，使用默认图标
	if icon == nil {
		ext := strings.ToLower(filepath.Ext(exePath))
		filename := strings.ToLower(filepath.Base(exePath))

		// 根据文件名选择图标
		switch {
		case filename == "explorer.exe":
			icon = theme.FolderOpenIcon()
		case filename == "cmd.exe" || filename == "powershell.exe":
			icon = theme.DownloadIcon() // 用于表示终端
		case strings.Contains(filename, "chrome") || strings.Contains(filename, "firefox"):
			icon = theme.ViewRefreshIcon() // 浏览器
		case strings.Contains(filename, "notepad"):
			icon = theme.DocumentIcon() // 文本编辑器
		case strings.Contains(filename, "player") || strings.Contains(filename, "music"):
			icon = theme.MediaPlayIcon() // 媒体播放器
		case ext == ".exe":
			icon = theme.HomeIcon() // 应用程序
		case ext == ".dll":
			icon = theme.FileIcon() // DLL文件
		default:
			icon = theme.ComputerIcon() // 默认图标
		}
	}

	// 添加到缓存
	iconCacheLock.Lock()
	iconCache[exePath] = icon
	iconCacheLock.Unlock()

	return icon
}
