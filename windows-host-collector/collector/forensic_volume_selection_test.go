package collector

import (
	"testing"
	"windows-host-collector/forensics/filesystem"
)

func TestSelectForensicVolumesReportsProbeFailuresBeforeUnsupportedFilesystem(t *testing.T) {
	input := []filesystem.VolumeInfo{
		{VolumeID: "vol:c", DriveLetter: "C:", FileSystem: "NTFS"},
		{VolumeID: "vol:d", DriveLetter: "D:", FilesystemProbeError: "device not ready"},
		{VolumeID: "vol:e", DriveLetter: "E:", FileSystem: "ReFS"},
	}

	selected, diagnostics := selectForensicVolumes(input)
	if len(selected) != 1 || selected[0].DriveLetter != "C:" {
		t.Fatalf("expected only C: to be selected, got %#v", selected)
	}
	if len(diagnostics.SkippedVolumes) != 2 {
		t.Fatalf("expected two skipped volume diagnostics, got %#v", diagnostics)
	}
	if diagnostics.SkippedVolumes[0].ReasonCode != "filesystem_probe_failed" ||
		diagnostics.SkippedVolumes[0].Evidence != "device not ready" {
		t.Fatalf("expected probe failure diagnostic first, got %#v", diagnostics.SkippedVolumes)
	}
	if diagnostics.SkippedVolumes[1].ReasonCode != "unsupported_filesystem" ||
		diagnostics.SkippedVolumes[1].FileSystem != "ReFS" {
		t.Fatalf("expected unsupported filesystem diagnostic second, got %#v", diagnostics.SkippedVolumes)
	}
}
