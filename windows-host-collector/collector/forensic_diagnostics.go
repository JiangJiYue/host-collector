package collector

import "windows-host-collector/forensics/filesystem"

func accumulateCollectorDiagnostics(total *filesystem.CollectorDiagnostics, delta filesystem.CollectorDiagnostics) {
	if total == nil {
		return
	}

	total.TotalRecordsRead += delta.TotalRecordsRead
	total.TotalParsedRecords += delta.TotalParsedRecords
	total.TotalEntriesEmitted += delta.TotalEntriesEmitted
	total.TotalFileEntriesEmitted += delta.TotalFileEntriesEmitted
	total.TotalDirectoryNodesEmitted += delta.TotalDirectoryNodesEmitted
	total.AllocatedEntryCount += delta.AllocatedEntryCount
	total.DeletedEntryCount += delta.DeletedEntryCount
	total.OrphanEntryCount += delta.OrphanEntryCount
	total.InternalNTFSObjectCount += delta.InternalNTFSObjectCount
	total.TimestampCoverageCreated += delta.TimestampCoverageCreated
	total.TimestampCoverageModified += delta.TimestampCoverageModified
	total.TimestampCoverageAccessed += delta.TimestampCoverageAccessed
	total.TimestampCoverageChanged += delta.TimestampCoverageChanged
	total.HashCoverageCount += delta.HashCoverageCount
	total.PathReconstructionFailureCount += delta.PathReconstructionFailureCount
	total.ReparsePointCount += delta.ReparsePointCount
	total.SkippedVolumes = append(total.SkippedVolumes, delta.SkippedVolumes...)
}
