//go:build windows
// +build windows

package collector

import (
	"fmt"
	"syscall"
	"unsafe"
	"windows-host-collector/models"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modpsapi    = syscall.NewLazyDLL("psapi.dll")
	moduser32   = syscall.NewLazyDLL("user32.dll")
	modntdll    = syscall.NewLazyDLL("ntdll.dll")

	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procModule32First            = modkernel32.NewProc("Module32FirstW")
	procModule32Next             = modkernel32.NewProc("Module32NextW")
	procProcessCloseHandle       = modkernel32.NewProc("CloseHandle")
	procProcessOpenProcess       = modkernel32.NewProc("OpenProcess")

	procEnumWindows              = moduser32.NewProc("EnumWindows")
	procGetWindowThreadProcessId = moduser32.NewProc("GetWindowThreadProcessId")
	procGetWindowTextW           = moduser32.NewProc("GetWindowTextW")
	procIsWindowVisible          = moduser32.NewProc("IsWindowVisible")
	procGetWindowRect            = moduser32.NewProc("GetWindowRect")
	procGetClassNameW            = moduser32.NewProc("GetClassNameW")

	procNtQuerySystemInformation        = modntdll.NewProc("NtQuerySystemInformation")
	procCreateToolhelp32SnapshotThreads = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First                   = modkernel32.NewProc("Thread32First")
	procThread32Next                    = modkernel32.NewProc("Thread32Next")
)

const (
	TH32CS_SNAPMODULE   = 0x00000008
	TH32CS_SNAPMODULE32 = 0x00000010
	TH32CS_SNAPTHREAD   = 0x00000004
)

type THREADENTRY32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

type MODULEENTRY32W struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	ModBaseAddr  *byte
	ModBaseSize  uint32
	Module       [256]uint16
	ExePath      [260]uint16
}

func collectProcessModules(pid int32) ([]models.ProcessModule, error) {
	// 用 OpenProcess + EnumProcessModules 替代 CreateToolhelp32Snapshot
	// PROCESS_QUERY_INFORMATION=0x0400, PROCESS_VM_READ=0x0010
	handle, _, _ := procProcessOpenProcess.Call(0x0400|0x0010, 0, uintptr(pid))
	if handle == 0 {
		return nil, fmt.Errorf("OpenProcess failed for PID %d", pid)
	}
	defer procProcessCloseHandle.Call(handle)

	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32),
		uintptr(pid),
	)
	if snapshot == 0 || snapshot == ^uintptr(0) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed for PID %d", pid)
	}
	defer procProcessCloseHandle.Call(snapshot)

	var me MODULEENTRY32W
	me.Size = uint32(unsafe.Sizeof(me))

	var modules []models.ProcessModule
	ret, _, _ := procModule32First.Call(snapshot, uintptr(unsafe.Pointer(&me)))
	if ret == 0 {
		return nil, fmt.Errorf("Module32First failed for PID %d", pid)
	}

	for {
		name := syscall.UTF16ToString(me.Module[:])
		path := syscall.UTF16ToString(me.ExePath[:])
		modules = append(modules, models.ProcessModule{
			ID:          fmt.Sprintf("mod-%d-%d", pid, len(modules)),
			Name:        name,
			Path:        path,
			BaseAddress: fmt.Sprintf("0x%x", uintptr(unsafe.Pointer(me.ModBaseAddr))),
			Size:        int64(me.ModBaseSize),
			EntryPoint:  "",
			IsSigned:    false,
		})
		ret, _, _ = procModule32Next.Call(snapshot, uintptr(unsafe.Pointer(&me)))
		if ret == 0 {
			break
		}
	}

	return modules, nil
}

func collectProcessWindows(pid int32) ([]models.ProcessWindow, error) {
	snapshot, err := snapshotProcessWindows()
	if err != nil {
		return nil, err
	}
	return snapshot[pid], nil
}

func snapshotProcessWindows() (map[int32][]models.ProcessWindow, error) {
	rows, err := enumerateProcessWindows()
	if err != nil {
		return nil, err
	}
	return groupProcessWindowsByPID(rows), nil
}

func enumerateProcessWindows() ([]enumeratedProcessWindow, error) {
	rows := make([]enumeratedProcessWindow, 0, 32)

	cb := syscall.NewCallback(func(hwnd syscall.Handle, lParam uintptr) uintptr {
		var winPID uint32
		threadID, _, _ := procGetWindowThreadProcessId.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&winPID)))
		if winPID == 0 {
			return 1
		}

		var titleBuf [512]uint16
		titleLen, _, _ := procGetWindowTextW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&titleBuf[0])), 512)
		title := ""
		if titleLen > 0 {
			title = syscall.UTF16ToString(titleBuf[:])
		}

		var classBuf [256]uint16
		classLen, _, _ := procGetClassNameW.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&classBuf[0])), 256)
		className := ""
		if classLen > 0 {
			className = syscall.UTF16ToString(classBuf[:])
		}

		var rect [4]int32
		procGetWindowRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&rect[0])))

		vis, _, _ := procIsWindowVisible.Call(uintptr(hwnd))
		visible := vis != 0

		rows = append(rows, enumeratedProcessWindow{
			PID: int32(winPID),
			Window: models.ProcessWindow{
				Handle:    fmt.Sprintf("0x%08x", hwnd),
				ThreadID:  int(threadID),
				ClassName: className,
				Title:     title,
				Rect:      [4]int{int(rect[0]), int(rect[1]), int(rect[2]), int(rect[3])},
				Visible:   visible,
			},
		})

		return 1
	})

	ret, _, callErr := procEnumWindows.Call(cb, 0)
	if ret == 0 {
		return nil, fmt.Errorf("EnumWindows failed: %v", callErr)
	}
	return rows, nil
}

type SYSTEM_HANDLE_TABLE_ENTRY_INFO struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

func collectProcessHandles(pid int32) ([]models.ProcessHandle, error) {
	var bufSize uint32 = 1024 * 1024
	buf := make([]byte, bufSize)

	var returnLen uint32
	status, _, _ := procNtQuerySystemInformation.Call(
		64,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bufSize),
		uintptr(unsafe.Pointer(&returnLen)),
	)

	if status != 0 && status != 0xC0000004 {
		return nil, fmt.Errorf("NtQuerySystemInformation failed: 0x%x", status)
	}

	if status == 0xC0000004 {
		bufSize = returnLen + 4096
		buf = make([]byte, bufSize)
		status, _, _ = procNtQuerySystemInformation.Call(
			64,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if status != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation retry failed: 0x%x", status)
		}
	}

	if len(buf) < 8 {
		return nil, fmt.Errorf("buffer too small")
	}

	processHandle, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		processHandle = 0
	} else {
		defer windows.CloseHandle(processHandle)
	}

	numberOfHandles := *(*uintptr)(unsafe.Pointer(&buf[0]))
	headerSize := unsafe.Sizeof(uintptr(0)) * 2
	entrySize := unsafe.Sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO{})
	var handles []models.ProcessHandle
	typeNameCache := make(map[uint16]string)

	for i := uintptr(0); i < numberOfHandles; i++ {
		offset := headerSize + i*entrySize
		if offset+entrySize > uintptr(len(buf)) {
			break
		}
		entry := (*SYSTEM_HANDLE_TABLE_ENTRY_INFO)(unsafe.Pointer(&buf[offset]))
		if int32(entry.UniqueProcessID) != pid {
			continue
		}

		objectType, attributes, typeName := formatHandleFallbackFields(entry.ObjectTypeIndex, entry.HandleAttributes)
		var objectName *string
		if processHandle != 0 {
			objectType, typeName, objectName = resolveHandleMetadata(processHandle, entry.HandleValue, entry.ObjectTypeIndex, typeNameCache)
		}
		handles = append(handles, models.ProcessHandle{
			ID:            fmt.Sprintf("handle-%d-%d", pid, len(handles)),
			PID:           int(entry.UniqueProcessID),
			ObjectType:    objectType,
			Attributes:    attributes,
			Value:         fmt.Sprintf("0x%x", entry.HandleValue),
			AccessMask:    fmt.Sprintf("0x%08x", entry.GrantedAccess),
			ObjectAddress: fmt.Sprintf("0x%x", entry.Object),
			TypeName:      typeName,
			ObjectName:    objectName,
		})
	}

	return handles, nil
}

func collectProcessThreads(pid int32) ([]models.ProcessThread, error) {
	snapshot, _, _ := procCreateToolhelp32SnapshotThreads.Call(uintptr(TH32CS_SNAPTHREAD), 0)
	if snapshot == 0 || snapshot == ^uintptr(0) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed for threads")
	}
	defer procProcessCloseHandle.Call(snapshot)

	var te THREADENTRY32
	te.Size = uint32(unsafe.Sizeof(te))
	var threads []models.ProcessThread

	ret, _, _ := procThread32First.Call(snapshot, uintptr(unsafe.Pointer(&te)))
	if ret == 0 {
		return nil, fmt.Errorf("Thread32First failed")
	}

	for {
		if int32(te.OwnerProcessID) == pid {
			threads = append(threads, models.ProcessThread{
				ThreadID: int(te.ThreadID),
				State:    "Running",
			})
		}
		ret, _, _ = procThread32Next.Call(snapshot, uintptr(unsafe.Pointer(&te)))
		if ret == 0 {
			break
		}
	}

	return threads, nil
}
