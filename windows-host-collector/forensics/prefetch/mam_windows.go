//go:build windows

package prefetch

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const compressionFormatXpressHuff = 0x0004

var (
	ntdll                              = windows.NewLazySystemDLL("ntdll.dll")
	procRtlDecompressBufferEx          = ntdll.NewProc("RtlDecompressBufferEx")
	procRtlGetCompressionWorkSpaceSize = ntdll.NewProc("RtlGetCompressionWorkSpaceSize")
)

var decompressMAMPayload = decompressMAMPayloadWindows

func decompressMAMPayloadWindows(payload []byte, expectedSize uint32) ([]byte, error) {
	if expectedSize == 0 {
		return nil, ErrTooSmall
	}
	if len(payload) == 0 {
		return nil, ErrTooSmall
	}

	var workspaceSize uint32
	var fragmentWorkspaceSize uint32
	status, _, _ := procRtlGetCompressionWorkSpaceSize.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafe.Pointer(&workspaceSize)),
		uintptr(unsafe.Pointer(&fragmentWorkspaceSize)),
	)
	if status != 0 {
		return nil, fmt.Errorf("RtlGetCompressionWorkSpaceSize status=0x%x", status)
	}
	if workspaceSize == 0 {
		return nil, fmt.Errorf("RtlGetCompressionWorkSpaceSize returned zero workspace")
	}

	output := make([]byte, expectedSize)
	workspace := make([]byte, workspaceSize)
	var finalSize uint32
	status, _, _ = procRtlDecompressBufferEx.Call(
		uintptr(compressionFormatXpressHuff),
		uintptr(unsafe.Pointer(&output[0])),
		uintptr(len(output)),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&finalSize)),
		uintptr(unsafe.Pointer(&workspace[0])),
	)
	if status != 0 {
		return nil, fmt.Errorf("RtlDecompressBufferEx status=0x%x", status)
	}
	if finalSize == 0 || finalSize > uint32(len(output)) {
		return nil, fmt.Errorf("invalid decompressed size: %d", finalSize)
	}
	return output[:finalSize], nil
}
