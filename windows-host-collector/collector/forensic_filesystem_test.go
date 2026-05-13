package collector

import (
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
	"windows-host-collector/forensics/filesystem"
	"windows-host-collector/forensics/ntfs"
)

func TestBuildForensicResultFromRecordsProducesVolumeEntriesAndTimeline(t *testing.T) {
	modifiedAt := time.Date(2026, time.April, 23, 1, 2, 3, 0, time.UTC)
	records := []ntfs.Record{
		{
			EntryNumber:    5,
			SequenceNumber: 1,
			Flags:          0x0003,
			IsAllocated:    true,
			IsDirectory:    true,
			FileName: ntfs.FileNameAttribute{
				ParentMFTEntry: 5,
				ParentSequence: 1,
				Name:           "",
				NameNamespace:  1,
			},
		},
		{
			EntryNumber:    42,
			SequenceNumber: 7,
			Flags:          0x0001,
			IsAllocated:    true,
			IsDirectory:    false,
			StandardInformation: ntfs.StandardInformation{
				CreatedAt:  modifiedAt,
				ModifiedAt: modifiedAt,
				ChangedAt:  modifiedAt,
				AccessedAt: modifiedAt,
			},
			FileName: ntfs.FileNameAttribute{
				ParentMFTEntry: 5,
				ParentSequence: 1,
				Name:           "note.txt",
				NameNamespace:  1,
				RealSize:       int64(len("hello world")),
				AllocatedSize:  4096,
				CreatedAt:      modifiedAt,
				ModifiedAt:     modifiedAt,
				ChangedAt:      modifiedAt,
				AccessedAt:     modifiedAt,
			},
		},
	}

	tmpDir := t.TempDir()
	hostFile := filepath.Join(tmpDir, "note.txt")
	if err := os.WriteFile(hostFile, []byte("hello world"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got := buildForensicResult(forensicCollectionInput{
		volume: filesystem.VolumeInfo{
			VolumeID:          "vol:c",
			DevicePath:        `\\.\C:`,
			DriveLetter:       "C:",
			FileSystem:        "NTFS",
			BytesPerSector:    512,
			SectorsPerCluster: 8,
			ClusterSize:       4096,
			MFTStartLCN:       4,
			FileRecordSize:    1024,
		},
		records: records,
		fileLocator: func(entry filesystem.FileEntry) string {
			if entry.Name == "note.txt" {
				return hostFile
			}
			return ""
		},
	})

	if len(got.Volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(got.Volumes))
	}
	if len(got.DirectoryNodes) != 1 {
		t.Fatalf("expected 1 directory node, got %d", len(got.DirectoryNodes))
	}
	if len(got.FileEntries) != 2 {
		t.Fatalf("expected 2 file entries including root, got %d", len(got.FileEntries))
	}
	if len(got.TimelineEvents) == 0 {
		t.Fatalf("expected timeline events, got %#v", got.TimelineEvents)
	}

	var fileRow filesystem.FileEntry
	for _, row := range got.FileEntries {
		if row.Name == "note.txt" {
			fileRow = row
			break
		}
	}
	if fileRow.EntryID == "" {
		t.Fatalf("expected note.txt row in %#v", got.FileEntries)
	}
	if fileRow.Path != `C:\note.txt` {
		t.Fatalf("expected Windows path C:\\note.txt, got %q", fileRow.Path)
	}
	if fileRow.ParentPath != `C:\` {
		t.Fatalf("expected Windows parent path C:\\, got %q", fileRow.ParentPath)
	}
	if fileRow.MimeType != "text/plain; charset=utf-8" {
		t.Fatalf("expected text mime type, got %q", fileRow.MimeType)
	}
	if fileRow.SHA256 == "" {
		t.Fatalf("expected sha256 to be populated, got %#v", fileRow)
	}
	if fileRow.HashState != "hashed" {
		t.Fatalf("expected hashState hashed, got %q", fileRow.HashState)
	}
	if got.Volumes[0].VolumeID != "vol:c" {
		t.Fatalf("expected canonical volume id vol:c, got %q", got.Volumes[0].VolumeID)
	}
	if got.Volumes[0].DriveLetter != "C:" {
		t.Fatalf("expected canonical drive letter C:, got %q", got.Volumes[0].DriveLetter)
	}
	if got.FileEntries[0].Path != `C:\` {
		t.Fatalf("expected canonical root path C:\\, got %q", got.FileEntries[0].Path)
	}
}

func TestCollectForensicVolumeFromReaderReadsBootSectorAndMFTRecords(t *testing.T) {
	modifiedAt := time.Date(2026, time.April, 23, 1, 2, 3, 0, time.UTC)
	boot := make([]byte, 512)
	copy(boot[3:11], []byte("NTFS    "))
	binary.LittleEndian.PutUint16(boot[11:13], 512)
	boot[13] = 8
	binary.LittleEndian.PutUint64(boot[48:56], 4)
	binary.LittleEndian.PutUint64(boot[56:64], 8)
	boot[64] = 246

	rootRecord := buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 5,
		sequence:    1,
		flags:       0x0003,
		parentEntry: 5,
		parentSeq:   1,
		name:        "",
		namespace:   1,
		realSize:    0,
		allocSize:   0,
		modifiedAt:  modifiedAt,
	})
	fileRecord := buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 42,
		sequence:    7,
		flags:       0x0001,
		parentEntry: 5,
		parentSeq:   1,
		name:        "note.txt",
		namespace:   1,
		realSize:    11,
		allocSize:   4096,
		modifiedAt:  modifiedAt,
	})

	image := make([]byte, 4*4096+2*1024)
	copy(image[:512], boot)
	copy(image[4*4096:4*4096+1024], rootRecord)
	copy(image[4*4096+1024:4*4096+2048], fileRecord)

	got, err := collectForensicVolumeFromReader(
		filesystem.VolumeInfo{
			VolumeID:    "vol:c",
			DevicePath:  `\\.\C:`,
			DriveLetter: "C:",
		},
		bytesReaderAt(image),
		2,
		func(entry filesystem.FileEntry) string { return "" },
	)
	if err != nil {
		t.Fatalf("collectForensicVolumeFromReader() error = %v", err)
	}
	if len(got.FileEntries) != 2 {
		t.Fatalf("expected 2 file entries, got %d", len(got.FileEntries))
	}
	if got.Volumes[0].ClusterSize != 4096 {
		t.Fatalf("expected cluster size 4096, got %d", got.Volumes[0].ClusterSize)
	}
	if got.Volumes[0].FileRecordSize != 1024 {
		t.Fatalf("expected file record size 1024, got %d", got.Volumes[0].FileRecordSize)
	}

	var noteRow filesystem.FileEntry
	for _, row := range got.FileEntries {
		if row.Name == "note.txt" {
			noteRow = row
			break
		}
	}
	if noteRow.EntryID == "" {
		t.Fatalf("expected note.txt row in %#v", got.FileEntries)
	}
	if noteRow.Path != `C:\note.txt` {
		t.Fatalf("expected Windows file path, got %q", noteRow.Path)
	}
}

func TestCollectForensicVolumeFromReaderReadsPastPrototypeRecordLimit(t *testing.T) {
	modifiedAt := time.Date(2026, time.April, 25, 1, 2, 3, 0, time.UTC)
	boot := make([]byte, 512)
	copy(boot[3:11], []byte("NTFS    "))
	binary.LittleEndian.PutUint16(boot[11:13], 512)
	boot[13] = 8
	binary.LittleEndian.PutUint64(boot[48:56], 4)
	binary.LittleEndian.PutUint64(boot[56:64], 8)
	boot[64] = 246

	rootRecord := buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 5,
		sequence:    1,
		flags:       0x0003,
		parentEntry: 5,
		parentSeq:   1,
		name:        "",
		namespace:   1,
		realSize:    0,
		allocSize:   0,
		modifiedAt:  modifiedAt,
	})
	fileRecord := buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 4095,
		sequence:    9,
		flags:       0x0001,
		parentEntry: 4096,
		parentSeq:   1,
		name:        "payload.exe",
		namespace:   1,
		realSize:    123,
		allocSize:   4096,
		modifiedAt:  modifiedAt,
	})
	parentRecord := buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 4096,
		sequence:    1,
		flags:       0x0003,
		parentEntry: 5,
		parentSeq:   1,
		name:        "Users",
		namespace:   1,
		realSize:    0,
		allocSize:   0,
		modifiedAt:  modifiedAt,
	})

	image := make([]byte, 4*4096+4097*1024)
	copy(image[:512], boot)
	copy(image[4*4096+5*1024:4*4096+6*1024], rootRecord)
	copy(image[4*4096+4095*1024:4*4096+4096*1024], fileRecord)
	copy(image[4*4096+4096*1024:4*4096+4097*1024], parentRecord)

	got, err := collectForensicVolumeFromReader(
		filesystem.VolumeInfo{
			VolumeID:    "vol:c",
			DevicePath:  `\\.\C:`,
			DriveLetter: "C:",
		},
		bytesReaderAt(image),
		4096,
		func(entry filesystem.FileEntry) string { return "" },
	)
	if err != nil {
		t.Fatalf("collectForensicVolumeFromReader() error = %v", err)
	}

	var fileRow filesystem.FileEntry
	for _, row := range got.FileEntries {
		if row.Name == "payload.exe" {
			fileRow = row
			break
		}
	}
	if fileRow.EntryID == "" {
		t.Fatalf("expected payload.exe row in %#v", got.FileEntries)
	}
	if fileRow.IsOrphan {
		t.Fatalf("expected payload.exe not to be orphan when parent exists later in MFT: %#v", fileRow)
	}
	if fileRow.Path != `C:\Users\payload.exe` {
		t.Fatalf("expected reconstructed path to include deferred parent, got %q", fileRow.Path)
	}
	if fileRow.ParentPath != `C:\Users` {
		t.Fatalf("expected parent path C:\\Users, got %q", fileRow.ParentPath)
	}
}

func TestCollectForensicVolumeFromReaderReadsDesktopEntriesFromSplitMFTDataRuns(t *testing.T) {
	modifiedAt := time.Date(2026, time.May, 7, 8, 16, 0, 0, time.UTC)
	boot := make([]byte, 512)
	copy(boot[3:11], []byte("NTFS    "))
	binary.LittleEndian.PutUint16(boot[11:13], 512)
	boot[13] = 8
	binary.LittleEndian.PutUint64(boot[48:56], 4)
	binary.LittleEndian.PutUint64(boot[56:64], 8)
	boot[64] = 246

	const clusterSize = 4096
	const recordSize = 1024
	image := make([]byte, 24*clusterSize)
	copy(image[:512], boot)

	writeRecordAtLogicalEntry := func(entryNumber int64, record []byte) {
		var physicalOffset int
		switch {
		case entryNumber >= 0 && entryNumber <= 3:
			physicalOffset = 4*clusterSize + int(entryNumber)*recordSize
		case entryNumber >= 4 && entryNumber <= 11:
			physicalOffset = 20*clusterSize + int(entryNumber-4)*recordSize
		default:
			t.Fatalf("test entry %d is outside configured MFT data runs", entryNumber)
		}
		copy(image[physicalOffset:physicalOffset+recordSize], record)
	}

	writeRecordAtLogicalEntry(0, buildCollectorMFTRecordWithDataRuns(modifiedAt, []collectorDataRunSpec{
		{lengthClusters: 1, lcnDelta: 4},
		{lengthClusters: 2, lcnDelta: 16},
	}))
	writeRecordAtLogicalEntry(5, buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 5, sequence: 1, flags: 0x0003, parentEntry: 5, parentSeq: 1, name: "", namespace: 1, modifiedAt: modifiedAt,
	}))
	writeRecordAtLogicalEntry(6, buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 6, sequence: 1, flags: 0x0003, parentEntry: 5, parentSeq: 1, name: "Users", namespace: 1, modifiedAt: modifiedAt,
	}))
	writeRecordAtLogicalEntry(7, buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 7, sequence: 1, flags: 0x0003, parentEntry: 6, parentSeq: 1, name: "48967", namespace: 1, modifiedAt: modifiedAt,
	}))
	writeRecordAtLogicalEntry(8, buildCollectorTestRecord(testCollectorRecordSpec{
		entryNumber: 8, sequence: 1, flags: 0x0003, parentEntry: 7, parentSeq: 1, name: "Desktop", namespace: 1, modifiedAt: modifiedAt,
	}))

	desktopEntries := []testCollectorRecordSpec{
		{entryNumber: 9, sequence: 1, flags: 0x0001, parentEntry: 8, parentSeq: 1, name: "Firefox.exe", namespace: 1, realSize: 392320, allocSize: 393216, modifiedAt: modifiedAt},
		{entryNumber: 10, sequence: 1, flags: 0x0001, parentEntry: 8, parentSeq: 1, name: `互联网企业“双月恳谈”工作座谈会 (1).pptx`, namespace: 1, realSize: 51024, allocSize: 53248, modifiedAt: modifiedAt},
		{entryNumber: 11, sequence: 1, flags: 0x0001, parentEntry: 8, parentSeq: 1, name: "WPS Office.lnk", namespace: 1, realSize: 2410, allocSize: 4096, modifiedAt: modifiedAt},
	}
	for _, spec := range desktopEntries {
		writeRecordAtLogicalEntry(spec.entryNumber, buildCollectorTestRecord(spec))
	}

	got, err := collectForensicVolumeFromReader(
		filesystem.VolumeInfo{
			VolumeID:    "vol:c",
			DevicePath:  `\\.\C:`,
			DriveLetter: "C:",
		},
		bytesReaderAt(image),
		4096,
		func(entry filesystem.FileEntry) string { return "" },
	)
	if err != nil {
		t.Fatalf("collectForensicVolumeFromReader() error = %v", err)
	}

	paths := map[string]filesystem.FileEntry{}
	for _, row := range got.FileEntries {
		paths[row.Path] = row
	}
	for _, expectedPath := range []string{
		`C:\Users\48967\Desktop`,
		`C:\Users\48967\Desktop\Firefox.exe`,
		`C:\Users\48967\Desktop\互联网企业“双月恳谈”工作座谈会 (1).pptx`,
		`C:\Users\48967\Desktop\WPS Office.lnk`,
	} {
		if _, ok := paths[expectedPath]; !ok {
			t.Fatalf("expected split-MFT collection to include %s, got paths %#v", expectedPath, paths)
		}
	}
}

func TestMFTDataRunReaderReadsRecordAcrossRunBoundary(t *testing.T) {
	image := make([]byte, 16)
	copy(image[4:8], []byte("FILE"))
	copy(image[12:16], []byte("data"))

	reader, err := newMFTDataRunReader(bytesReaderAt(image), []ntfs.DataRun{
		{VCNStart: 0, LengthClusters: 1, LCN: 1},
		{VCNStart: 1, LengthClusters: 1, LCN: 3},
	}, 4, 8)
	if err != nil {
		t.Fatalf("newMFTDataRunReader() error = %v", err)
	}

	buf := make([]byte, 8)
	n, err := reader.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("ReadAt() error = %v", err)
	}
	if n != 8 || string(buf) != "FILEdata" {
		t.Fatalf("expected cross-run read to preserve logical data, n=%d buf=%q", n, string(buf))
	}
}

func TestBuildForensicResultEmitsTimestampCoverageDiagnostics(t *testing.T) {
	modifiedAt := time.Date(2026, time.April, 25, 1, 2, 3, 0, time.UTC)

	got := buildForensicResult(buildForensicResultDiagnosticsFixture(modifiedAt))

	if len(got.FileEntries) != 2 {
		t.Fatalf("expected 2 file entries, got %d", len(got.FileEntries))
	}

	var file filesystem.FileEntry
	for _, row := range got.FileEntries {
		if row.Name == "payload.exe" {
			file = row
			break
		}
	}
	if file.EntryID == "" {
		t.Fatalf("expected payload.exe row in %#v", got.FileEntries)
	}
	if file.CreatedAt == "" || file.ModifiedAt == "" || file.AccessedAt == "" || file.ChangedAt == "" {
		t.Fatalf("expected four timestamps to be populated: %#v", file)
	}
	if file.CreatedTimestampSource != "standard_information" {
		t.Fatalf("expected created timestamp source standard_information, got %#v", file)
	}
	if file.ModifiedTimestampSource != "standard_information" {
		t.Fatalf("expected modified timestamp source standard_information, got %#v", file)
	}
	if file.AccessedTimestampSource != "standard_information" {
		t.Fatalf("expected accessed timestamp source standard_information, got %#v", file)
	}
	if file.ChangedTimestampSource != "standard_information" {
		t.Fatalf("expected changed timestamp source standard_information, got %#v", file)
	}
	if got.Diagnostics.TimestampCoverageCreated == 0 {
		t.Fatalf("expected timestamp coverage diagnostics: %#v", got.Diagnostics)
	}
	if got.Diagnostics.TimestampCoverageModified == 0 {
		t.Fatalf("expected modified timestamp coverage diagnostics: %#v", got.Diagnostics)
	}
	if got.Diagnostics.TimestampCoverageAccessed == 0 {
		t.Fatalf("expected accessed timestamp coverage diagnostics: %#v", got.Diagnostics)
	}
	if got.Diagnostics.TimestampCoverageChanged == 0 {
		t.Fatalf("expected changed timestamp coverage diagnostics: %#v", got.Diagnostics)
	}
	if got.Diagnostics.TotalParsedRecords != 2 {
		t.Fatalf("expected parsed record count 2, got %#v", got.Diagnostics)
	}
	if got.Diagnostics.TotalEntriesEmitted != 2 {
		t.Fatalf("expected total emitted entry count 2, got %#v", got.Diagnostics)
	}
	if got.Diagnostics.TotalFileEntriesEmitted != 1 {
		t.Fatalf("expected file-only emitted entry count 1, got %#v", got.Diagnostics)
	}
}

func TestBuildForensicResultFallsBackToFileNameTimestampsWhenSIIsMissing(t *testing.T) {
	fnTime := time.Date(2026, time.April, 25, 5, 6, 7, 0, time.UTC)

	got := buildForensicResult(forensicCollectionInput{
		volume: filesystem.VolumeInfo{
			VolumeID:    "vol:c",
			DriveLetter: "C:",
		},
		records: []ntfs.Record{
			{
				EntryNumber:    5,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           "",
					NameNamespace:  1,
				},
			},
			{
				EntryNumber:    77,
				SequenceNumber: 1,
				Flags:          0x0001,
				IsAllocated:    true,
				IsDirectory:    false,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           "fallback.txt",
					NameNamespace:  1,
					RealSize:       8,
					AllocatedSize:  4096,
					CreatedAt:      fnTime,
					ModifiedAt:     fnTime,
					AccessedAt:     fnTime,
					ChangedAt:      fnTime,
				},
			},
		},
	})

	var file filesystem.FileEntry
	for _, row := range got.FileEntries {
		if row.Name == "fallback.txt" {
			file = row
			break
		}
	}
	if file.EntryID == "" {
		t.Fatalf("expected fallback.txt row in %#v", got.FileEntries)
	}
	if file.CreatedAt == "" || file.ModifiedAt == "" || file.AccessedAt == "" || file.ChangedAt == "" {
		t.Fatalf("expected fallback timestamps to be populated from FN: %#v", file)
	}
	if file.CreatedTimestampSource != "file_name" || file.ModifiedTimestampSource != "file_name" || file.AccessedTimestampSource != "file_name" || file.ChangedTimestampSource != "file_name" {
		t.Fatalf("expected all timestamp sources to be file_name, got %#v", file)
	}
	if got.Diagnostics.TimestampCoverageCreated != 1 || got.Diagnostics.TimestampCoverageModified != 1 || got.Diagnostics.TimestampCoverageAccessed != 1 || got.Diagnostics.TimestampCoverageChanged != 1 {
		t.Fatalf("expected timestamp coverage diagnostics to count FN fallback row, got %#v", got.Diagnostics)
	}
}

func TestBuildForensicResultKeepsExplorerVisibleTreeWhenNtfsRootUsesDotName(t *testing.T) {
	modifiedAt := time.Date(2026, time.April, 25, 8, 9, 10, 0, time.UTC)

	got := buildForensicResult(forensicCollectionInput{
		volume: filesystem.VolumeInfo{
			VolumeID:    "vol:c",
			DriveLetter: "C:",
		},
		records: []ntfs.Record{
			{
				EntryNumber:    5,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           "",
					NameNamespace:  1,
				},
			},
			{
				EntryNumber:    24,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           ".",
					NameNamespace:  1,
				},
			},
			{
				EntryNumber:    40,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 24,
					ParentSequence: 1,
					Name:           "Windows",
					NameNamespace:  1,
					ModifiedAt:     modifiedAt,
				},
			},
			{
				EntryNumber:    41,
				SequenceNumber: 1,
				Flags:          0x0001,
				IsAllocated:    true,
				IsDirectory:    false,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 40,
					ParentSequence: 1,
					Name:           "explorer.exe",
					NameNamespace:  1,
					RealSize:       123,
					AllocatedSize:  4096,
					ModifiedAt:     modifiedAt,
				},
			},
		},
	})

	var windowsDir filesystem.FileEntry
	var explorerFile filesystem.FileEntry
	for _, row := range got.FileEntries {
		switch row.Name {
		case "Windows":
			windowsDir = row
		case "explorer.exe":
			explorerFile = row
		}
	}

	if windowsDir.EntryID == "" {
		t.Fatalf("expected Windows directory in explorer-visible entries, got %#v", got.FileEntries)
	}
	if explorerFile.EntryID == "" {
		t.Fatalf("expected explorer.exe file in explorer-visible entries, got %#v", got.FileEntries)
	}
	if windowsDir.IsInternalNTFSObject {
		t.Fatalf("Windows directory must not be flagged as internal ntfs object: %#v", windowsDir)
	}
	if windowsDir.Path != `C:\Windows` {
		t.Fatalf("expected Windows directory path C:\\Windows, got %q", windowsDir.Path)
	}
	if explorerFile.Path != `C:\Windows\explorer.exe` {
		t.Fatalf("expected explorer.exe path under Windows directory, got %q", explorerFile.Path)
	}
	if explorerFile.ParentPath != `C:\Windows` {
		t.Fatalf("expected explorer.exe parent path C:\\Windows, got %q", explorerFile.ParentPath)
	}
}

func TestBuildForensicResultCountsInternalNTFSObjectsSeparatelyFromOrphans(t *testing.T) {
	modifiedAt := time.Date(2026, time.April, 25, 12, 13, 14, 0, time.UTC)

	got := buildForensicResult(forensicCollectionInput{
		volume: filesystem.VolumeInfo{
			VolumeID:    "vol:c",
			DriveLetter: "C:",
		},
		records: []ntfs.Record{
			{
				EntryNumber:    5,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           "",
					NameNamespace:  1,
				},
			},
			{
				EntryNumber:    24,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           ".",
					NameNamespace:  1,
					ModifiedAt:     modifiedAt,
				},
			},
			{
				EntryNumber:    42,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 24,
					ParentSequence: 1,
					Name:           "$Extend",
					NameNamespace:  1,
					ModifiedAt:     modifiedAt,
				},
			},
		},
	})

	if got.Diagnostics.InternalNTFSObjectCount != 2 {
		t.Fatalf("expected two internal ntfs objects, got %#v", got.Diagnostics)
	}
	if got.Diagnostics.OrphanEntryCount != 0 {
		t.Fatalf("expected internal ntfs objects not to inflate orphan count, got %#v", got.Diagnostics)
	}
}

func TestBuildForensicResultOmitsInternalNTFSObjectsFromExplorerVisibleOutput(t *testing.T) {
	modifiedAt := time.Date(2026, time.April, 25, 15, 16, 17, 0, time.UTC)

	got := buildForensicResult(forensicCollectionInput{
		volume: filesystem.VolumeInfo{
			VolumeID:    "vol:c",
			DriveLetter: "C:",
		},
		records: []ntfs.Record{
			{
				EntryNumber:    5,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           "",
					NameNamespace:  1,
				},
			},
			{
				EntryNumber:    24,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           ".",
					NameNamespace:  1,
					ModifiedAt:     modifiedAt,
				},
			},
			{
				EntryNumber:    42,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 24,
					ParentSequence: 1,
					Name:           "$Extend",
					NameNamespace:  1,
					ModifiedAt:     modifiedAt,
				},
			},
			{
				EntryNumber:    99,
				SequenceNumber: 1,
				Flags:          0x0001,
				IsAllocated:    true,
				IsDirectory:    false,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           "note.txt",
					NameNamespace:  1,
					RealSize:       12,
					AllocatedSize:  4096,
					ModifiedAt:     modifiedAt,
				},
			},
		},
	})

	if len(got.FileEntries) != 2 {
		t.Fatalf("expected only root and Explorer-visible file in output, got %#v", got.FileEntries)
	}
	if len(got.DirectoryNodes) != 1 {
		t.Fatalf("expected only root directory node in Explorer-visible output, got %#v", got.DirectoryNodes)
	}
	for _, entry := range got.FileEntries {
		if entry.IsInternalNTFSObject {
			t.Fatalf("did not expect internal ntfs object in default file entries: %#v", got.FileEntries)
		}
	}
	if got.Diagnostics.InternalNTFSObjectCount != 2 {
		t.Fatalf("expected diagnostics to retain internal ntfs object count, got %#v", got.Diagnostics)
	}
	if got.Diagnostics.TotalEntriesEmitted != 2 {
		t.Fatalf("expected emitted entries to reflect Explorer-visible rows only, got %#v", got.Diagnostics)
	}
	if got.Diagnostics.TotalDirectoryNodesEmitted != 1 {
		t.Fatalf("expected emitted directory nodes to reflect Explorer-visible rows only, got %#v", got.Diagnostics)
	}
	if got.Diagnostics.TotalFileEntriesEmitted != 1 {
		t.Fatalf("expected emitted file count to reflect Explorer-visible rows only, got %#v", got.Diagnostics)
	}
}

func buildForensicResultDiagnosticsFixture(timestamp time.Time) forensicCollectionInput {
	return forensicCollectionInput{
		volume: filesystem.VolumeInfo{
			VolumeID:    "vol:c",
			DriveLetter: "C:",
		},
		records: []ntfs.Record{
			{
				EntryNumber:    5,
				SequenceNumber: 1,
				Flags:          0x0003,
				IsAllocated:    true,
				IsDirectory:    true,
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           "",
					NameNamespace:  1,
				},
			},
			{
				EntryNumber:    42,
				SequenceNumber: 1,
				Flags:          0x0001,
				IsAllocated:    true,
				IsDirectory:    false,
				StandardInformation: ntfs.StandardInformation{
					CreatedAt:  timestamp,
					ModifiedAt: timestamp,
					AccessedAt: timestamp,
					ChangedAt:  timestamp,
				},
				FileName: ntfs.FileNameAttribute{
					ParentMFTEntry: 5,
					ParentSequence: 1,
					Name:           "payload.exe",
					NameNamespace:  1,
					RealSize:       123,
					AllocatedSize:  4096,
				},
			},
		},
	}
}

type bytesReaderAt []byte

func (b bytesReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(b)) {
		return 0, io.EOF
	}
	n := copy(p, b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

type testCollectorRecordSpec struct {
	entryNumber int64
	sequence    uint16
	flags       uint16
	parentEntry int64
	parentSeq   uint16
	name        string
	namespace   uint8
	realSize    int64
	allocSize   int64
	modifiedAt  time.Time
}

func buildCollectorTestRecord(spec testCollectorRecordSpec) []byte {
	record := make([]byte, 1024)
	copy(record[0:4], []byte("FILE"))

	usaCount := uint16(len(record)/512 + 1)
	binary.LittleEndian.PutUint16(record[4:6], 0x30)
	binary.LittleEndian.PutUint16(record[6:8], usaCount)
	binary.LittleEndian.PutUint16(record[16:18], spec.sequence)
	binary.LittleEndian.PutUint16(record[20:22], 0x38)
	binary.LittleEndian.PutUint16(record[22:24], spec.flags)
	binary.LittleEndian.PutUint32(record[24:28], 1024)
	binary.LittleEndian.PutUint32(record[28:32], 1024)

	usn := uint16(0xaaaa)
	binary.LittleEndian.PutUint16(record[0x30:0x32], usn)
	for i := 1; i < int(usaCount); i++ {
		replacement := uint16(0x1100 + i)
		binary.LittleEndian.PutUint16(record[0x30+i*2:0x32+i*2], replacement)
		sectorEnd := i*512 - 2
		binary.LittleEndian.PutUint16(record[sectorEnd:sectorEnd+2], usn)
	}

	offset := 0x38
	offset = writeCollectorResidentAttribute(record, offset, 0x10, buildCollectorStandardInformation(spec.modifiedAt))
	offset = writeCollectorResidentAttribute(record, offset, 0x30, buildCollectorFileNameValue(spec))
	binary.LittleEndian.PutUint32(record[offset:offset+4], 0xffffffff)
	return record
}

type collectorDataRunSpec struct {
	lengthClusters int64
	lcnDelta       int64
}

func buildCollectorMFTRecordWithDataRuns(modifiedAt time.Time, runs []collectorDataRunSpec) []byte {
	record := make([]byte, 1024)
	copy(record[0:4], []byte("FILE"))

	usaCount := uint16(len(record)/512 + 1)
	binary.LittleEndian.PutUint16(record[4:6], 0x30)
	binary.LittleEndian.PutUint16(record[6:8], usaCount)
	binary.LittleEndian.PutUint16(record[16:18], 1)
	binary.LittleEndian.PutUint16(record[20:22], 0x38)
	binary.LittleEndian.PutUint16(record[22:24], 0x0001)
	binary.LittleEndian.PutUint32(record[24:28], 1024)
	binary.LittleEndian.PutUint32(record[28:32], 1024)

	usn := uint16(0xaaaa)
	binary.LittleEndian.PutUint16(record[0x30:0x32], usn)
	for i := 1; i < int(usaCount); i++ {
		replacement := uint16(0x1100 + i)
		binary.LittleEndian.PutUint16(record[0x30+i*2:0x32+i*2], replacement)
		sectorEnd := i*512 - 2
		binary.LittleEndian.PutUint16(record[sectorEnd:sectorEnd+2], usn)
	}

	mftSpec := testCollectorRecordSpec{
		entryNumber: 0,
		sequence:    1,
		flags:       0x0001,
		parentEntry: 5,
		parentSeq:   1,
		name:        "$MFT",
		namespace:   1,
		realSize:    3 * 4096,
		allocSize:   3 * 4096,
		modifiedAt:  modifiedAt,
	}
	offset := 0x38
	offset = writeCollectorResidentAttribute(record, offset, 0x10, buildCollectorStandardInformation(modifiedAt))
	offset = writeCollectorResidentAttribute(record, offset, 0x30, buildCollectorFileNameValue(mftSpec))
	offset = writeCollectorNonResidentDataAttribute(record, offset, encodeCollectorDataRuns(runs), mftSpec.allocSize, mftSpec.realSize)
	binary.LittleEndian.PutUint32(record[offset:offset+4], 0xffffffff)
	return record
}

func writeCollectorNonResidentDataAttribute(record []byte, offset int, runlist []byte, allocatedSize int64, realSize int64) int {
	const headerLength = 64
	attrLen := alignCollector8(headerLength + len(runlist))
	binary.LittleEndian.PutUint32(record[offset:offset+4], 0x80)
	binary.LittleEndian.PutUint32(record[offset+4:offset+8], uint32(attrLen))
	record[offset+8] = 1
	record[offset+9] = 0
	binary.LittleEndian.PutUint16(record[offset+10:offset+12], 0)
	binary.LittleEndian.PutUint16(record[offset+12:offset+14], 0)
	binary.LittleEndian.PutUint16(record[offset+14:offset+16], 0)
	binary.LittleEndian.PutUint64(record[offset+16:offset+24], 0)
	binary.LittleEndian.PutUint64(record[offset+24:offset+32], uint64(allocatedSize/4096-1))
	binary.LittleEndian.PutUint16(record[offset+32:offset+34], headerLength)
	binary.LittleEndian.PutUint16(record[offset+34:offset+36], 0)
	binary.LittleEndian.PutUint64(record[offset+40:offset+48], uint64(allocatedSize))
	binary.LittleEndian.PutUint64(record[offset+48:offset+56], uint64(realSize))
	binary.LittleEndian.PutUint64(record[offset+56:offset+64], uint64(realSize))
	copy(record[offset+headerLength:offset+headerLength+len(runlist)], runlist)
	return offset + attrLen
}

func encodeCollectorDataRuns(runs []collectorDataRunSpec) []byte {
	encoded := make([]byte, 0, len(runs)*3+1)
	for _, run := range runs {
		encoded = append(encoded, 0x11, byte(run.lengthClusters), byte(run.lcnDelta))
	}
	return append(encoded, 0)
}

func writeCollectorResidentAttribute(record []byte, offset int, attrType uint32, value []byte) int {
	attrLen := alignCollector8(24 + len(value))
	binary.LittleEndian.PutUint32(record[offset:offset+4], attrType)
	binary.LittleEndian.PutUint32(record[offset+4:offset+8], uint32(attrLen))
	record[offset+8] = 0
	record[offset+9] = 0
	binary.LittleEndian.PutUint16(record[offset+10:offset+12], 0)
	binary.LittleEndian.PutUint16(record[offset+12:offset+14], 0)
	binary.LittleEndian.PutUint16(record[offset+14:offset+16], 0)
	binary.LittleEndian.PutUint32(record[offset+16:offset+20], uint32(len(value)))
	binary.LittleEndian.PutUint16(record[offset+20:offset+22], 24)
	record[offset+22] = 0
	record[offset+23] = 0
	copy(record[offset+24:offset+24+len(value)], value)
	return offset + attrLen
}

func buildCollectorStandardInformation(modifiedAt time.Time) []byte {
	value := make([]byte, 0x30)
	filetime := collectorTimeToFiletime(modifiedAt)
	for _, off := range []int{0x00, 0x08, 0x10, 0x18} {
		binary.LittleEndian.PutUint64(value[off:off+8], filetime)
	}
	return value
}

func buildCollectorFileNameValue(spec testCollectorRecordSpec) []byte {
	nameUTF16 := utf16.Encode([]rune(spec.name))
	value := make([]byte, 0x42+len(nameUTF16)*2)
	parentRef := (uint64(spec.parentSeq) << 48) | uint64(spec.parentEntry)
	binary.LittleEndian.PutUint64(value[0x00:0x08], parentRef)
	filetime := collectorTimeToFiletime(spec.modifiedAt)
	for _, off := range []int{0x08, 0x10, 0x18, 0x20} {
		binary.LittleEndian.PutUint64(value[off:off+8], filetime)
	}
	binary.LittleEndian.PutUint64(value[0x28:0x30], uint64(spec.allocSize))
	binary.LittleEndian.PutUint64(value[0x30:0x38], uint64(spec.realSize))
	binary.LittleEndian.PutUint32(value[0x38:0x3c], uint32(spec.flags))
	value[0x40] = byte(len(nameUTF16))
	value[0x41] = spec.namespace
	for i, r := range nameUTF16 {
		binary.LittleEndian.PutUint16(value[0x42+i*2:0x44+i*2], r)
	}
	return value
}

func collectorTimeToFiletime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	const windowsEpochOffset = 116444736000000000
	return uint64(t.UTC().UnixNano()/100) + windowsEpochOffset
}

func alignCollector8(n int) int {
	if n%8 == 0 {
		return n
	}
	return n + (8 - (n % 8))
}
