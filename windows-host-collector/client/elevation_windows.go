//go:build windows

package client

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func EnsureElevated() error {
	if isAdmin() {
		return nil
	}
	return relaunchWithRunAs()
}

func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid,
	)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, _ := token.IsMember(sid)
	return member
}

func relaunchWithRunAs() error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve current executable: %w", err)
	}

	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecute := shell32.NewProc("ShellExecuteW")

	verbPtr, _ := syscall.UTF16PtrFromString("runas")
	exePtr, _ := syscall.UTF16PtrFromString(exePath)
	argsPtr, _ := syscall.UTF16PtrFromString(strings.Join(os.Args[1:], " "))
	dirPtr, _ := syscall.UTF16PtrFromString("")

	ret, _, callErr := shellExecute.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argsPtr)),
		uintptr(unsafe.Pointer(dirPtr)),
		1,
	)
	if ret <= 32 {
		if callErr != syscall.Errno(0) {
			return fmt.Errorf("request administrator relaunch: %w", callErr)
		}
		return fmt.Errorf("request administrator relaunch failed with code %d", ret)
	}

	return fmt.Errorf("administrator relaunch requested; retry the scan in the elevated window")
}
