package collector

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"windows-host-collector/forensics/filesystem"
	forensichash "windows-host-collector/forensics/hash"
	forensicmime "windows-host-collector/forensics/mime"
	"windows-host-collector/forensics/ntfs"
	"windows-host-collector/utils"
)

type ForensicFileSystemCollector struct{}

const minMFTInvalidRecordTolerance = 4096

type ForensicFileSystemResult struct {
	Volumes        []filesystem.VolumeInfo         `json:"forensicVolumes"`
	DirectoryNodes []filesystem.DirectoryNode      `json:"forensicDirectoryNodes"`
	FileEntries    []filesystem.FileEntry          `json:"forensicFileEntries"`
	TimelineEvents []filesystem.TimelineEvent      `json:"forensicTimelineEvents"`
	Diagnostics    filesystem.CollectorDiagnostics `json:"forensicDiagnostics"`
}

func NewForensicFileSystemCollector() *ForensicFileSystemCollector {
	return &ForensicFileSystemCollector{}
}

func (c *ForensicFileSystemCollector) Name() string {
	return "forensic_file_system"
}

type readerAt interface {
	ReadAt(p []byte, off int64) (int, error)
}

type forensicCollectionInput struct {
	volume      filesystem.VolumeInfo
	records     []ntfs.Record
	fileLocator func(filesystem.FileEntry) string
}

func buildForensicResult(input forensicCollectionInput) *ForensicFileSystemResult {
	rows := make([]filesystem.RawEntry, 0, len(input.records))
	diagnostics := filesystem.CollectorDiagnostics{
		TotalParsedRecords: len(input.records),
	}
	for _, record := range input.records {
		createdAt := formatNTFSTime(record.StandardInformation.CreatedAt)
		modifiedAt := formatNTFSTime(record.StandardInformation.ModifiedAt)
		accessedAt := formatNTFSTime(record.StandardInformation.AccessedAt)
		changedAt := formatNTFSTime(record.StandardInformation.ChangedAt)
		fnCreatedAt := formatNTFSTime(record.FileName.CreatedAt)
		fnModifiedAt := formatNTFSTime(record.FileName.ModifiedAt)
		fnAccessedAt := formatNTFSTime(record.FileName.AccessedAt)
		fnChangedAt := formatNTFSTime(record.FileName.ChangedAt)

		row := filesystem.RawEntry{
			VolumeID:                input.volume.VolumeID,
			MFTEntry:                record.EntryNumber,
			MFTSequence:             int64(record.SequenceNumber),
			ParentMFTEntry:          record.FileName.ParentMFTEntry,
			Name:                    record.FileName.Name,
			IsDirectory:             record.IsDirectory,
			IsDeleted:               !record.IsAllocated,
			IsAllocated:             record.IsAllocated,
			Size:                    record.FileName.RealSize,
			AllocatedSize:           record.FileName.AllocatedSize,
			TimestampSource:         "standard_information",
			CreatedTimestampSource:  timestampSourceFor(createdAt, fnCreatedAt),
			ModifiedTimestampSource: timestampSourceFor(modifiedAt, fnModifiedAt),
			AccessedTimestampSource: timestampSourceFor(accessedAt, fnAccessedAt),
			ChangedTimestampSource:  timestampSourceFor(changedAt, fnChangedAt),
			CreatedAt:               selectTimestamp(createdAt, fnCreatedAt),
			ModifiedAt:              selectTimestamp(modifiedAt, fnModifiedAt),
			AccessedAt:              selectTimestamp(accessedAt, fnAccessedAt),
			ChangedAt:               selectTimestamp(changedAt, fnChangedAt),
			SICreatedAt:             createdAt,
			SIModifiedAt:            modifiedAt,
			SIAccessedAt:            accessedAt,
			SIChangedAt:             changedAt,
			FNCreatedAt:             fnCreatedAt,
			FNModifiedAt:            fnModifiedAt,
			FNAccessedAt:            fnAccessedAt,
			FNChangedAt:             fnChangedAt,
			NameType:                ntfsNameNamespace(record.FileName.NameNamespace),
			RecordFlags:             ntfsRecordFlags(record),
		}
		if row.ModifiedTimestampSource == "file_name" {
			row.TimestampSource = "file_name"
		}
		rows = append(rows, row)
	}

	entries := filesystem.RebuildPaths(rows)
	normalizeWindowsPaths(input.volume.DriveLetter, entries)
	for index := range entries {
		enrichFileEntry(&entries[index], input.fileLocator)
	}

	for _, entry := range entries {
		if entry.IsAllocated {
			diagnostics.AllocatedEntryCount++
		} else {
			diagnostics.DeletedEntryCount++
		}
		if entry.IsOrphan {
			diagnostics.OrphanEntryCount++
		}
		if entry.IsInternalNTFSObject {
			diagnostics.InternalNTFSObjectCount++
		}
		if entry.PathReconstructionFailed {
			diagnostics.PathReconstructionFailureCount++
		}
		if entry.CreatedAt != "" {
			diagnostics.TimestampCoverageCreated++
		}
		if entry.ModifiedAt != "" {
			diagnostics.TimestampCoverageModified++
		}
		if entry.AccessedAt != "" {
			diagnostics.TimestampCoverageAccessed++
		}
		if entry.ChangedAt != "" {
			diagnostics.TimestampCoverageChanged++
		}
		if entry.MD5 != "" || entry.SHA1 != "" || entry.SHA256 != "" {
			diagnostics.HashCoverageCount++
		}
	}

	explorerEntries := filterExplorerVisibleEntries(entries)
	directoryNodes := buildDirectoryNodes(explorerEntries)
	timelineEvents := buildTimelineEvents(explorerEntries)
	diagnostics.TotalEntriesEmitted = len(explorerEntries)
	diagnostics.TotalDirectoryNodesEmitted = len(directoryNodes)
	for _, entry := range explorerEntries {
		if entry.IsDirectory {
			continue
		}
		diagnostics.TotalFileEntriesEmitted++
	}

	return &ForensicFileSystemResult{
		Volumes:        []filesystem.VolumeInfo{input.volume},
		DirectoryNodes: directoryNodes,
		FileEntries:    explorerEntries,
		TimelineEvents: timelineEvents,
		Diagnostics:    diagnostics,
	}
}

func collectForensicVolumeFromReader(
	volumeInfo filesystem.VolumeInfo,
	reader readerAt,
	maxRecords int,
	fileLocator func(filesystem.FileEntry) string,
) (*ForensicFileSystemResult, error) {
	bootSectorBytes := make([]byte, 512)
	if _, err := reader.ReadAt(bootSectorBytes, 0); err != nil && err != io.EOF {
		return nil, fmt.Errorf("read boot sector: %w", err)
	}

	boot, err := ntfs.ParseBootSector(bootSectorBytes)
	if err != nil {
		return nil, err
	}

	volumeInfo.BytesPerSector = boot.BytesPerSector
	volumeInfo.SectorsPerCluster = boot.SectorsPerCluster
	volumeInfo.ClusterSize = boot.ClusterSize
	volumeInfo.MFTStartLCN = boot.MFTStartLCN
	volumeInfo.FileRecordSize = boot.FileRecordSize
	if volumeInfo.FileSystem == "" {
		volumeInfo.FileSystem = "NTFS"
	}

	initialRecordTarget := maxRecords
	if initialRecordTarget <= 0 {
		initialRecordTarget = 1024
	}
	recordSize := int(boot.FileRecordSize)
	if recordSize <= 0 {
		return nil, fmt.Errorf("invalid file record size %d", boot.FileRecordSize)
	}

	records := make([]ntfs.Record, 0, initialRecordTarget)
	mftOffset := boot.MFTStartLCN * boot.ClusterSize
	mftRecord, mftErr := readNTFSRecord(reader, mftOffset, recordSize, int(boot.BytesPerSector), 0)
	if mftErr == nil && len(mftRecord.DataRuns) > 0 {
		records, err = readMFTRecordsFromDataRuns(reader, mftRecord.DataRuns, boot.ClusterSize, recordSize, int(boot.BytesPerSector), mftRecord.DataSize)
		if err != nil {
			return nil, err
		}
		return buildForensicResult(forensicCollectionInput{
			volume:      volumeInfo,
			records:     records,
			fileLocator: fileLocator,
		}), nil
	}

	invalidTolerance := initialRecordTarget
	if invalidTolerance < minMFTInvalidRecordTolerance {
		invalidTolerance = minMFTInvalidRecordTolerance
	}
	consecutiveInvalidRecords := 0

	for index := 0; ; index++ {
		offset := mftOffset + int64(index*recordSize)
		record, readRecordErr := readNTFSRecord(reader, offset, recordSize, int(boot.BytesPerSector), int64(index))
		if readRecordErr != nil {
			if readRecordErr == io.EOF {
				break
			}
			consecutiveInvalidRecords++
			if index >= initialRecordTarget && consecutiveInvalidRecords >= invalidTolerance {
				break
			}
			continue
		}
		consecutiveInvalidRecords = 0
		records = append(records, record)
	}

	return buildForensicResult(forensicCollectionInput{
		volume:      volumeInfo,
		records:     records,
		fileLocator: fileLocator,
	}), nil
}

func readMFTRecordsFromDataRuns(
	reader readerAt,
	runs []ntfs.DataRun,
	clusterSize int64,
	recordSize int,
	bytesPerSector int,
	dataSize int64,
) ([]ntfs.Record, error) {
	records := make([]ntfs.Record, 0)
	mftReader, err := newMFTDataRunReader(reader, runs, clusterSize, dataSize)
	if err != nil {
		return nil, err
	}
	recordsInMFT := mftReader.size / int64(recordSize)
	for index := int64(0); index < recordsInMFT; index++ {
		record, err := readNTFSRecord(mftReader, index*int64(recordSize), recordSize, bytesPerSector, index)
		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}
		records = append(records, record)
	}
	return records, nil
}

type mftDataRunReader struct {
	reader      readerAt
	runs        []ntfs.DataRun
	clusterSize int64
	size        int64
}

func newMFTDataRunReader(reader readerAt, runs []ntfs.DataRun, clusterSize int64, dataSize int64) (*mftDataRunReader, error) {
	if clusterSize <= 0 {
		return nil, fmt.Errorf("invalid cluster size %d", clusterSize)
	}
	size := dataSize
	if size <= 0 {
		for _, run := range runs {
			end := (run.VCNStart + run.LengthClusters) * clusterSize
			if end > size {
				size = end
			}
		}
	}
	return &mftDataRunReader{
		reader:      reader,
		runs:        runs,
		clusterSize: clusterSize,
		size:        size,
	}, nil
}

func (r *mftDataRunReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset %d", off)
	}
	if off >= r.size {
		return 0, io.EOF
	}

	total := 0
	for total < len(p) && off+int64(total) < r.size {
		logicalOffset := off + int64(total)
		run, runOffset, ok := r.runForLogicalOffset(logicalOffset)
		if !ok {
			if total > 0 {
				return total, io.EOF
			}
			return 0, io.EOF
		}

		availableInRun := run.LengthClusters*r.clusterSize - runOffset
		remainingSize := r.size - logicalOffset
		remainingBuffer := int64(len(p) - total)
		toRead := minInt64(availableInRun, minInt64(remainingSize, remainingBuffer))
		if toRead <= 0 {
			break
		}

		physicalOffset := run.LCN*r.clusterSize + runOffset
		n, err := r.reader.ReadAt(p[total:total+int(toRead)], physicalOffset)
		total += n
		if err != nil {
			return total, err
		}
		if n < int(toRead) {
			return total, io.EOF
		}
	}

	if total < len(p) {
		return total, io.EOF
	}
	return total, nil
}

func (r *mftDataRunReader) runForLogicalOffset(offset int64) (ntfs.DataRun, int64, bool) {
	vcn := offset / r.clusterSize
	for _, run := range r.runs {
		if vcn < run.VCNStart || vcn >= run.VCNStart+run.LengthClusters {
			continue
		}
		runLogicalStart := run.VCNStart * r.clusterSize
		return run, offset - runLogicalStart, true
	}
	return ntfs.DataRun{}, 0, false
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func readNTFSRecord(
	reader readerAt,
	offset int64,
	recordSize int,
	bytesPerSector int,
	entryNumber int64,
) (ntfs.Record, error) {
	recordBytes := make([]byte, recordSize)
	n, readErr := reader.ReadAt(recordBytes, offset)
	if readErr != nil && readErr != io.EOF {
		return ntfs.Record{}, fmt.Errorf("read MFT record %d: %w", entryNumber, readErr)
	}
	if n < 4 {
		return ntfs.Record{}, io.EOF
	}
	if string(recordBytes[:4]) != "FILE" {
		if readErr == io.EOF {
			return ntfs.Record{}, io.EOF
		}
		return ntfs.Record{}, fmt.Errorf("invalid MFT record signature")
	}
	record, err := ntfs.ParseRecordWithSectorSize(recordBytes, entryNumber, bytesPerSector)
	if err != nil {
		return ntfs.Record{}, err
	}
	return record, nil
}

func normalizeWindowsPaths(driveLetter string, entries []filesystem.FileEntry) {
	prefix := strings.TrimSpace(driveLetter)
	if prefix == "" {
		return
	}
	if !strings.HasSuffix(prefix, `:`) {
		prefix += `:`
	}
	root := prefix + `\`

	for index := range entries {
		entry := &entries[index]
		if entry.Path == `\` {
			entry.Path = root
			entry.ParentPath = ""
			if entry.Name == "" {
				entry.Name = prefix
			}
			continue
		}
		entry.Path = prefix + entry.Path
		switch entry.ParentPath {
		case "":
		case `\`:
			entry.ParentPath = root
		default:
			entry.ParentPath = prefix + entry.ParentPath
		}
	}
}

func filterExplorerVisibleEntries(entries []filesystem.FileEntry) []filesystem.FileEntry {
	filtered := make([]filesystem.FileEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsInternalNTFSObject {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func buildDirectoryNodes(entries []filesystem.FileEntry) []filesystem.DirectoryNode {
	nodes := make([]filesystem.DirectoryNode, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDirectory {
			continue
		}
		nodes = append(nodes, filesystem.DirectoryNode{
			NodeID:         entry.EntryID,
			VolumeID:       entry.VolumeID,
			MFTEntry:       entry.MFTEntry,
			MFTSequence:    entry.MFTSequence,
			ParentMFTEntry: entry.ParentMFTEntry,
			Path:           entry.Path,
			ParentPath:     entry.ParentPath,
			Name:           entry.Name,
			IsOrphan:       entry.IsOrphan,
		})
	}
	return nodes
}

func buildTimelineEvents(entries []filesystem.FileEntry) []filesystem.TimelineEvent {
	events := make([]filesystem.TimelineEvent, 0, len(entries)*4)
	for _, entry := range entries {
		for _, candidate := range []struct {
			eventType string
			timestamp string
			source    string
		}{
			{eventType: "created", timestamp: entry.CreatedAt, source: entry.CreatedTimestampSource},
			{eventType: "modified", timestamp: entry.ModifiedAt, source: entry.ModifiedTimestampSource},
			{eventType: "accessed", timestamp: entry.AccessedAt, source: entry.AccessedTimestampSource},
			{eventType: "changed", timestamp: entry.ChangedAt, source: entry.ChangedTimestampSource},
		} {
			if candidate.timestamp == "" {
				continue
			}
			events = append(events, filesystem.TimelineEvent{
				EventID:   entry.EntryID + ":" + candidate.eventType + ":" + candidate.timestamp,
				VolumeID:  entry.VolumeID,
				EntryID:   entry.EntryID,
				Path:      entry.Path,
				EventType: candidate.eventType,
				Timestamp: candidate.timestamp,
				Source:    candidate.source,
			})
		}
	}
	return events
}

func selectTimestamp(primary string, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}

func timestampSourceFor(primary string, fallback string) string {
	if primary != "" {
		return "standard_information"
	}
	if fallback != "" {
		return "file_name"
	}
	return ""
}

func enrichFileEntry(entry *filesystem.FileEntry, fileLocator func(filesystem.FileEntry) string) {
	if entry == nil {
		return
	}

	decision := forensichash.DefaultPolicy().Decide(entry.Size, entry.IsDirectory)
	entry.HashState = decision.State
	if fileLocator == nil || entry.IsDirectory {
		return
	}

	hostPath := fileLocator(*entry)
	if hostPath == "" {
		return
	}

	data, err := os.ReadFile(hostPath)
	if err != nil {
		entry.ParseWarnings = append(entry.ParseWarnings, "content_unavailable")
		return
	}

	header := data
	if len(header) > 512 {
		header = header[:512]
	}
	entry.MimeType = forensicmime.Detect(entry.Name, header)

	if decision.State != forensichash.StatePending {
		return
	}

	for _, algorithm := range decision.Algorithms {
		switch algorithm {
		case "md5":
			sum := md5.Sum(data)
			entry.MD5 = hex.EncodeToString(sum[:])
		case "sha1":
			sum := sha1.Sum(data)
			entry.SHA1 = hex.EncodeToString(sum[:])
		case "sha256":
			sum := sha256.Sum256(data)
			entry.SHA256 = hex.EncodeToString(sum[:])
		}
	}
	if len(decision.Algorithms) > 0 {
		entry.HashState = "hashed"
	}
}

func formatNTFSTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return utils.FormatTimeRFC3339(value.UTC())
}

func ntfsNameNamespace(namespace uint8) string {
	switch namespace {
	case 0:
		return "posix"
	case 1:
		return "win32"
	case 2:
		return "dos"
	case 3:
		return "win32_and_dos"
	default:
		return ""
	}
}

func ntfsRecordFlags(record ntfs.Record) []string {
	flags := make([]string, 0, 2)
	if record.IsAllocated {
		flags = append(flags, "allocated")
	}
	if record.IsDirectory {
		flags = append(flags, "directory")
	}
	return flags
}
