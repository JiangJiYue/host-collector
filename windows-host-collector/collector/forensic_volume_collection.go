package collector

import (
	"context"
	"windows-host-collector/forensics/filesystem"
	"windows-host-collector/utils"
)

type readerAtCloser interface {
	readerAt
	Close() error
}

type forensicVolumeOpener func(filesystem.VolumeInfo) (readerAtCloser, error)

type forensicVolumeCollector func(filesystem.VolumeInfo, readerAt) (*ForensicFileSystemResult, error)

func collectSelectedForensicVolumes(
	ctx context.Context,
	volumes []filesystem.VolumeInfo,
	openVolume forensicVolumeOpener,
	collectVolume forensicVolumeCollector,
) (*ForensicFileSystemResult, error) {
	result := &ForensicFileSystemResult{
		Volumes:        []filesystem.VolumeInfo{},
		DirectoryNodes: []filesystem.DirectoryNode{},
		FileEntries:    []filesystem.FileEntry{},
		TimelineEvents: []filesystem.TimelineEvent{},
	}

	for _, volumeInfo := range volumes {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		reader, err := openVolume(volumeInfo)
		if err != nil {
			utils.LogError("Collector", "打开卷失败 %s: %v", volumeInfo.DevicePath, err)
			appendSkippedVolumeDiagnostic(&result.Diagnostics, volumeInfo, "raw_volume_open_failed", err.Error())
			continue
		}

		volumeResult, collectErr := collectVolume(volumeInfo, reader)
		_ = reader.Close()
		if collectErr != nil {
			utils.LogError("Collector", "卷取证采集失败 %s: %v", volumeInfo.DevicePath, collectErr)
			appendSkippedVolumeDiagnostic(&result.Diagnostics, volumeInfo, "raw_volume_collect_failed", collectErr.Error())
			continue
		}

		result.Volumes = append(result.Volumes, volumeResult.Volumes...)
		result.DirectoryNodes = append(result.DirectoryNodes, volumeResult.DirectoryNodes...)
		result.FileEntries = append(result.FileEntries, volumeResult.FileEntries...)
		result.TimelineEvents = append(result.TimelineEvents, volumeResult.TimelineEvents...)
		accumulateCollectorDiagnostics(&result.Diagnostics, volumeResult.Diagnostics)
	}

	return result, nil
}

func appendSkippedVolumeDiagnostic(
	diagnostics *filesystem.CollectorDiagnostics,
	volumeInfo filesystem.VolumeInfo,
	reasonCode string,
	evidence string,
) {
	if diagnostics == nil {
		return
	}
	diagnostics.SkippedVolumes = append(diagnostics.SkippedVolumes, filesystem.VolumeSkipDiagnostic{
		VolumeID:    volumeInfo.VolumeID,
		DriveLetter: volumeInfo.DriveLetter,
		FileSystem:  volumeInfo.FileSystem,
		ReasonCode:  reasonCode,
		Evidence:    evidence,
	})
}
