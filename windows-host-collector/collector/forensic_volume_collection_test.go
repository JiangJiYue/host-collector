package collector

import (
	"context"
	"errors"
	"io"
	"testing"
	"windows-host-collector/forensics/filesystem"
)

func TestCollectSelectedForensicVolumesReportsOpenAndCollectFailures(t *testing.T) {
	volumes := []filesystem.VolumeInfo{
		{VolumeID: "vol:c", DevicePath: `\\.\C:`, DriveLetter: "C:", FileSystem: "NTFS"},
		{VolumeID: "vol:d", DevicePath: `\\.\D:`, DriveLetter: "D:", FileSystem: "NTFS"},
	}
	readers := map[string]readerAt{
		`\\.\D:`: failingReaderAt{err: io.ErrUnexpectedEOF},
	}

	got, err := collectSelectedForensicVolumes(
		context.Background(),
		volumes,
		func(volumeInfo filesystem.VolumeInfo) (readerAtCloser, error) {
			reader, ok := readers[volumeInfo.DevicePath]
			if !ok {
				return nil, errors.New("access denied")
			}
			return noopReadCloser{readerAt: reader}, nil
		},
		func(volumeInfo filesystem.VolumeInfo, reader readerAt) (*ForensicFileSystemResult, error) {
			return collectForensicVolumeFromReader(volumeInfo, reader, 1, nil)
		},
	)
	if err != nil {
		t.Fatalf("collectSelectedForensicVolumes() error = %v", err)
	}

	if len(got.Volumes) != 0 || len(got.FileEntries) != 0 {
		t.Fatalf("expected failed volumes not to emit forensic rows, got %#v", got)
	}
	if len(got.Diagnostics.SkippedVolumes) != 2 {
		t.Fatalf("expected two skipped volume diagnostics, got %#v", got.Diagnostics)
	}
	if got.Diagnostics.SkippedVolumes[0].ReasonCode != "raw_volume_open_failed" ||
		got.Diagnostics.SkippedVolumes[0].DriveLetter != "C:" ||
		got.Diagnostics.SkippedVolumes[0].Evidence != "access denied" {
		t.Fatalf("expected open failure diagnostic for C:, got %#v", got.Diagnostics.SkippedVolumes)
	}
	if got.Diagnostics.SkippedVolumes[1].ReasonCode != "raw_volume_collect_failed" ||
		got.Diagnostics.SkippedVolumes[1].DriveLetter != "D:" {
		t.Fatalf("expected collect failure diagnostic for D:, got %#v", got.Diagnostics.SkippedVolumes)
	}
}

type noopReadCloser struct {
	readerAt readerAt
}

func (r noopReadCloser) ReadAt(p []byte, off int64) (int, error) {
	return r.readerAt.ReadAt(p, off)
}

func (r noopReadCloser) Close() error {
	return nil
}

type failingReaderAt struct {
	err error
}

func (r failingReaderAt) ReadAt(_ []byte, _ int64) (int, error) {
	return 0, r.err
}
