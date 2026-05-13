//go:build windows

package collector

import (
	"context"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
	"windows-host-collector/forensics/filesystem"
	"windows-host-collector/forensics/volume"
)

var (
	procGetLogicalDriveStringsW = kernel32.NewProc("GetLogicalDriveStringsW")
	procGetVolumeInformationW   = kernel32.NewProc("GetVolumeInformationW")
)

func (c *ForensicFileSystemCollector) Collect(ctx context.Context) (interface{}, error) {
	volumes, err := enumerateWindowsVolumes(defaultWindowsVolumeProbe{})
	if err != nil {
		return nil, err
	}
	volumes, selectionDiagnostics := selectForensicVolumes(volumes)

	result, collectErr := collectSelectedForensicVolumes(
		ctx,
		volumes,
		func(volumeInfo filesystem.VolumeInfo) (readerAtCloser, error) {
			return volume.Open(volumeInfo.DevicePath)
		},
		func(volumeInfo filesystem.VolumeInfo, reader readerAt) (*ForensicFileSystemResult, error) {
			return collectForensicVolumeFromReader(volumeInfo, reader, 4096, nil)
		},
	)
	if collectErr != nil {
		return nil, collectErr
	}
	accumulateCollectorDiagnostics(&result.Diagnostics, selectionDiagnostics)

	return result, nil
}

type windowsVolumeProbe interface {
	LogicalDrives() ([]string, error)
	FilesystemName(rootPath string) (string, error)
}

type defaultWindowsVolumeProbe struct{}

func (defaultWindowsVolumeProbe) LogicalDrives() ([]string, error) {
	const bufferChars = 512
	buffer := make([]uint16, bufferChars)
	ret, _, callErr := procGetLogicalDriveStringsW.Call(
		uintptr(bufferChars),
		uintptr(unsafe.Pointer(&buffer[0])),
	)
	if ret == 0 {
		return nil, fmt.Errorf("GetLogicalDriveStringsW failed: %v", callErr)
	}

	joined := syscall.UTF16ToString(buffer)
	drives := make([]string, 0)
	for _, drive := range strings.Split(joined, "\x00") {
		drive = strings.TrimSpace(drive)
		if drive == "" {
			continue
		}
		drives = append(drives, drive)
	}
	return drives, nil
}

func (defaultWindowsVolumeProbe) FilesystemName(rootPath string) (string, error) {
	rootPathPtr, err := syscall.UTF16PtrFromString(rootPath)
	if err != nil {
		return "", err
	}
	fsName := make([]uint16, 64)
	ret, _, callErr := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(rootPathPtr)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&fsName[0])),
		uintptr(len(fsName)),
	)
	if ret == 0 {
		return "", fmt.Errorf("GetVolumeInformationW failed for %s: %v", rootPath, callErr)
	}
	return strings.TrimSpace(syscall.UTF16ToString(fsName)), nil
}

func enumerateWindowsVolumes(probe windowsVolumeProbe) ([]filesystem.VolumeInfo, error) {
	rawDrives, err := probe.LogicalDrives()
	if err != nil {
		return nil, err
	}
	volumes := make([]filesystem.VolumeInfo, 0, len(rawDrives))
	for _, drive := range rawDrives {
		drive = strings.TrimSpace(drive)
		if drive == "" {
			continue
		}
		letter := strings.TrimRight(drive, `\/`)
		normalizedLetter := strings.ToUpper(letter)
		devicePath, err := volume.NormalizeVolumePath(letter)
		if err != nil {
			continue
		}
		filesystemName, probeErr := probe.FilesystemName(drive)
		probeError := ""
		if probeErr != nil {
			filesystemName = ""
			probeError = probeErr.Error()
		}
		volumes = append(volumes, filesystem.VolumeInfo{
			VolumeID:             "vol:" + strings.ToLower(strings.TrimSuffix(normalizedLetter, ":")),
			DevicePath:           devicePath,
			DriveLetter:          normalizedLetter,
			FileSystem:           filesystemName,
			FilesystemProbeError: probeError,
		})
	}
	return volumes, nil
}
