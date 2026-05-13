package upload

import "strings"

func NormalizeMetadata(metadata Metadata, defaultScanType string) Metadata {
	metadata.AgentID = strings.TrimSpace(metadata.AgentID)
	metadata.ScanID = strings.TrimSpace(metadata.ScanID)
	metadata.ScanType = strings.TrimSpace(metadata.ScanType)
	metadata.CollectedAt = strings.TrimSpace(metadata.CollectedAt)
	if metadata.ScanType == "" {
		metadata.ScanType = strings.TrimSpace(defaultScanType)
	}
	return metadata
}
