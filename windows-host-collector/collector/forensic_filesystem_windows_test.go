//go:build windows

package collector

import (
	"errors"
	"testing"
	"windows-host-collector/forensics/filesystem"
)

func TestAccumulateCollectorDiagnosticsAddsVolumeCounters(t *testing.T) {
	total := filesystem.CollectorDiagnostics{
		TotalParsedRecords:        2,
		TotalEntriesEmitted:       3,
		TotalFileEntriesEmitted:   1,
		TimestampCoverageModified: 1,
	}

	accumulateCollectorDiagnostics(&total, filesystem.CollectorDiagnostics{
		TotalParsedRecords:             4,
		TotalEntriesEmitted:            5,
		TotalFileEntriesEmitted:        2,
		TimestampCoverageModified:      3,
		PathReconstructionFailureCount: 1,
	})

	if total.TotalParsedRecords != 6 {
		t.Fatalf("expected total parsed records 6, got %#v", total)
	}
	if total.TotalEntriesEmitted != 8 {
		t.Fatalf("expected total emitted entries 8, got %#v", total)
	}
	if total.TotalFileEntriesEmitted != 3 {
		t.Fatalf("expected total file entries 3, got %#v", total)
	}
	if total.TimestampCoverageModified != 4 {
		t.Fatalf("expected modified coverage 4, got %#v", total)
	}
	if total.PathReconstructionFailureCount != 1 {
		t.Fatalf("expected path reconstruction failure count 1, got %#v", total)
	}
}

func TestSelectForensicVolumesKeepsAllNTFSVolumesAndReportsSkippedVolumes(t *testing.T) {
	input := []filesystem.VolumeInfo{
		{VolumeID: "vol:c", DriveLetter: "C:", FileSystem: "NTFS"},
		{VolumeID: "vol:d", DriveLetter: "D:", FileSystem: "NTFS"},
		{VolumeID: "vol:e", DriveLetter: "E:", FileSystem: "ReFS"},
		{VolumeID: "vol:unknown", DriveLetter: "F:"},
	}

	got, diagnostics := selectForensicVolumes(input)
	if len(got) != 2 {
		t.Fatalf("expected both NTFS volumes to remain, got %#v", got)
	}
	if got[0].DriveLetter != "C:" || got[1].DriveLetter != "D:" {
		t.Fatalf("expected C: and D: NTFS volumes, got %#v", got)
	}
	if len(diagnostics.SkippedVolumes) != 2 {
		t.Fatalf("expected skipped volume diagnostics for non-NTFS/unknown filesystems, got %#v", diagnostics)
	}
	if diagnostics.SkippedVolumes[0].ReasonCode != "unsupported_filesystem" {
		t.Fatalf("expected unsupported filesystem reason, got %#v", diagnostics.SkippedVolumes)
	}
}

func TestEnumerateWindowsVolumesPreservesDetectedFilesystem(t *testing.T) {
	probe := fakeWindowsVolumeProbe{
		drives: []string{`C:\`, `D:\`, `E:\`},
		filesystems: map[string]string{
			`C:\`: "NTFS",
			`D:\`: "NTFS",
			`E:\`: "ReFS",
		},
	}

	got, err := enumerateWindowsVolumes(probe)
	if err != nil {
		t.Fatalf("enumerateWindowsVolumes() error = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected three volumes, got %#v", got)
	}
	if got[0].FileSystem != "NTFS" || got[1].FileSystem != "NTFS" || got[2].FileSystem != "ReFS" {
		t.Fatalf("expected detected filesystem names to be preserved, got %#v", got)
	}
	if got[2].DriveLetter != "E:" || got[2].VolumeID != "vol:e" || got[2].DevicePath != `\\.\E:` {
		t.Fatalf("expected canonical E: volume fields, got %#v", got[2])
	}
}

func TestSelectForensicVolumesReportsFilesystemProbeFailure(t *testing.T) {
	probe := fakeWindowsVolumeProbe{
		drives: []string{`C:\`, `D:\`},
		filesystems: map[string]string{
			`C:\`: "NTFS",
		},
		filesystemErrors: map[string]error{
			`D:\`: errors.New("device not ready"),
		},
	}

	volumes, err := enumerateWindowsVolumes(probe)
	if err != nil {
		t.Fatalf("enumerateWindowsVolumes() error = %v", err)
	}
	selected, diagnostics := selectForensicVolumes(volumes)
	if len(selected) != 1 || selected[0].DriveLetter != "C:" {
		t.Fatalf("expected only C: to be selected, got %#v", selected)
	}
	if len(diagnostics.SkippedVolumes) != 1 {
		t.Fatalf("expected one skipped volume diagnostic, got %#v", diagnostics)
	}
	skipped := diagnostics.SkippedVolumes[0]
	if skipped.DriveLetter != "D:" || skipped.ReasonCode != "filesystem_probe_failed" {
		t.Fatalf("expected D: filesystem probe failure diagnostic, got %#v", skipped)
	}
	if skipped.Evidence != "device not ready" {
		t.Fatalf("expected probe error evidence, got %#v", skipped)
	}
}

type fakeWindowsVolumeProbe struct {
	drives           []string
	filesystems      map[string]string
	filesystemErrors map[string]error
}

func (p fakeWindowsVolumeProbe) LogicalDrives() ([]string, error) {
	return p.drives, nil
}

func (p fakeWindowsVolumeProbe) FilesystemName(rootPath string) (string, error) {
	if err := p.filesystemErrors[rootPath]; err != nil {
		return "", err
	}
	return p.filesystems[rootPath], nil
}
