//go:build windows

package collector

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type privilegeRestore func() error

func enablePrivilege(name string) (privilegeRestore, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}

	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return nil, err
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		token.Close()
		return nil, err
	}

	newState := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}
	var previousState windows.Tokenprivileges
	returnLen := uint32(0)

	if err := windows.AdjustTokenPrivileges(
		token,
		false,
		&newState,
		uint32(unsafe.Sizeof(previousState)),
		&previousState,
		&returnLen,
	); err != nil {
		token.Close()
		return nil, err
	}
	if err := windows.GetLastError(); err != nil && err != windows.ERROR_SUCCESS {
		token.Close()
		if err == windows.ERROR_NOT_ALL_ASSIGNED {
			return nil, fmt.Errorf("adjust token privileges for %q: %w", name, err)
		}
		return nil, err
	}

	restore := func() error {
		defer token.Close()

		if returnLen == 0 {
			return nil
		}
		if err := windows.AdjustTokenPrivileges(
			token,
			false,
			&previousState,
			uint32(unsafe.Sizeof(previousState)),
			nil,
			nil,
		); err != nil {
			return err
		}
		if err := windows.GetLastError(); err != nil && err != windows.ERROR_SUCCESS {
			return err
		}
		return nil
	}

	return restore, nil
}
