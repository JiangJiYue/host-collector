//go:build windows

package collector

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	objectNameInformationClass = 1
	objectTypeInformationClass = 2

	statusSuccess            = 0x00000000
	statusBufferOverflow     = 0x80000005
	statusBufferTooSmall     = 0xC0000023
	statusInfoLengthMismatch = 0xC0000004

	maxHandleObjectNameChars = 4096
)

var procNtQueryObject = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject")

var ErrHandleQueryTimeout = errors.New("handle query timed out")

type ntUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

func resolveHandleMetadata(process windows.Handle, handleValue uintptr, objectTypeIndex uint16, cache map[uint16]string) (string, string, *string) {
	fallbackType, _, fallbackName := formatHandleFallbackFields(objectTypeIndex, 0)

	duplicated, err := duplicateHandleForQuery(process, handleValue)
	if err != nil {
		return fallbackType, fallbackName, nil
	}
	defer windows.CloseHandle(duplicated)

	typeName := cache[objectTypeIndex]
	if typeName == "" {
		typeName, _ = queryObjectUnicodeString(duplicated, objectTypeInformationClass)
		if typeName != "" {
			cache[objectTypeIndex] = typeName
		}
	}
	if typeName == "" {
		typeName = fallbackName
	}

	var objectName *string
	if shouldResolveHandleName(typeName) {
		if resolvedName, err := queryObjectUnicodeString(duplicated, objectNameInformationClass); err == nil && resolvedName != "" {
			objectName = &resolvedName
		}
	}

	return typeName, typeName, objectName
}

func duplicateHandleForQuery(process windows.Handle, handleValue uintptr) (windows.Handle, error) {
	currentProcess, err := windows.GetCurrentProcess()
	if err != nil {
		return 0, err
	}

	var duplicated windows.Handle
	if err := windows.DuplicateHandle(process, windows.Handle(handleValue), currentProcess, &duplicated, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return 0, err
	}
	return duplicated, nil
}

func queryObjectUnicodeString(handle windows.Handle, infoClass uintptr) (string, error) {
	bufSize := uint32(512)

	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, bufSize)
		var returnLen uint32

		status, _, callErr := procNtQueryObject.Call(
			uintptr(handle),
			infoClass,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&returnLen)),
		)

		switch uint32(status) {
		case statusSuccess:
			return decodeNTUnicodeString(buf, maxHandleObjectNameChars), nil
		case statusBufferOverflow, statusBufferTooSmall, statusInfoLengthMismatch:
			if returnLen <= bufSize {
				returnLen = bufSize * 2
			}
			bufSize = returnLen
			continue
		default:
			if errno, ok := callErr.(syscall.Errno); ok && errno != 0 {
				return "", errno
			}
			return "", syscall.Errno(status)
		}
	}

	return "", syscall.ERROR_INSUFFICIENT_BUFFER
}

func decodeNTUnicodeString(buf []byte, maxChars int) string {
	if len(buf) < int(unsafe.Sizeof(ntUnicodeString{})) {
		return ""
	}

	value := (*ntUnicodeString)(unsafe.Pointer(&buf[0]))
	if value.Buffer == nil || value.Length == 0 {
		return ""
	}
	if value.Length > value.MaximumLength {
		return ""
	}
	charCount := int(value.Length / 2)
	if maxChars > 0 && charCount > maxChars {
		return ""
	}
	bufferStart := uintptr(unsafe.Pointer(&buf[0]))
	bufferEnd := bufferStart + uintptr(len(buf))
	valueStart := uintptr(unsafe.Pointer(value.Buffer))
	valueEnd := valueStart + uintptr(value.Length)
	if valueStart < bufferStart || valueEnd < valueStart || valueEnd > bufferEnd {
		return ""
	}

	chars := unsafe.Slice(value.Buffer, charCount)
	return syscall.UTF16ToString(chars)
}
