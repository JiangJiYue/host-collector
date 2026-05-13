//go:build windows

package collector

import (
	"fmt"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
	"golang.org/x/sys/windows"
)

var procGetProcessHandleCount = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")

func getProcessHandleCount(p *process.Process) *int {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.Pid))
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(handle)

	var count uint32
	ret, _, _ := procGetProcessHandleCount.Call(uintptr(handle), uintptr(unsafe.Pointer(&count)))
	if ret == 0 {
		return nil
	}

	result := int(count)
	return &result
}

func getProcessBaseAddress(p *process.Process) *string {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(p.Pid))
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(handle)

	var module windows.Handle
	var cbNeeded uint32
	if err := windows.EnumProcessModules(handle, &module, uint32(unsafe.Sizeof(module)), &cbNeeded); err != nil {
		return nil
	}

	var moduleInfo windows.ModuleInfo
	if err := windows.GetModuleInformation(handle, module, &moduleInfo, uint32(unsafe.Sizeof(moduleInfo))); err != nil {
		return nil
	}

	baseAddress := fmt.Sprintf("0x%x", moduleInfo.BaseOfDll)
	return &baseAddress
}
