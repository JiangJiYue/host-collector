package collector

import (
	"strings"
	"windows-host-collector/forensics/filesystem"
)

func selectForensicVolumes(volumes []filesystem.VolumeInfo) ([]filesystem.VolumeInfo, filesystem.CollectorDiagnostics) {
	selected := make([]filesystem.VolumeInfo, 0, len(volumes))
	diagnostics := filesystem.CollectorDiagnostics{}
	for _, volumeInfo := range volumes {
		if strings.TrimSpace(volumeInfo.FilesystemProbeError) != "" {
			diagnostics.SkippedVolumes = append(diagnostics.SkippedVolumes, filesystem.VolumeSkipDiagnostic{
				VolumeID:    volumeInfo.VolumeID,
				DriveLetter: volumeInfo.DriveLetter,
				FileSystem:  volumeInfo.FileSystem,
				ReasonCode:  "filesystem_probe_failed",
				Evidence:    volumeInfo.FilesystemProbeError,
			})
			continue
		}

		filesystemName := strings.TrimSpace(volumeInfo.FileSystem)
		if !strings.EqualFold(filesystemName, "NTFS") {
			diagnostics.SkippedVolumes = append(diagnostics.SkippedVolumes, filesystem.VolumeSkipDiagnostic{
				VolumeID:    volumeInfo.VolumeID,
				DriveLetter: volumeInfo.DriveLetter,
				FileSystem:  volumeInfo.FileSystem,
				ReasonCode:  "unsupported_filesystem",
				Evidence:    filesystemName,
			})
			continue
		}
		selected = append(selected, volumeInfo)
	}
	return selected, diagnostics
}
