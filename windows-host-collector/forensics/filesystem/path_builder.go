package filesystem

import (
	"path"
	"strings"
)

func RebuildPaths(rows []RawEntry) []FileEntry {
	byID := make(map[string]RawEntry, len(rows))
	for _, row := range rows {
		byID[keyFor(row.VolumeID, row.MFTEntry)] = row
	}

	result := make([]FileEntry, 0, len(rows))
	for _, row := range rows {
		fullPath, parentPath, orphan, reconstructionFailed := buildPath(row, byID)
		isInternalNTFSObject := isInternalNTFSPath(fullPath)
		hashState := row.HashState
		if hashState == "" {
			hashState = "pending"
		}

		result = append(result, FileEntry{
			EntryID:                  keyFor(row.VolumeID, row.MFTEntry),
			VolumeID:                 row.VolumeID,
			MFTEntry:                 row.MFTEntry,
			MFTSequence:              row.MFTSequence,
			ParentMFTEntry:           row.ParentMFTEntry,
			Path:                     fullPath,
			ParentPath:               parentPath,
			Name:                     row.Name,
			Extension:                fileExtension(row.Name, row.IsDirectory),
			IsDirectory:              row.IsDirectory,
			IsDeleted:                row.IsDeleted,
			IsAllocated:              row.IsAllocated,
			IsOrphan:                 orphan,
			IsInternalNTFSObject:     isInternalNTFSObject,
			PathReconstructionFailed: reconstructionFailed,
			Size:                     row.Size,
			AllocatedSize:            row.AllocatedSize,
			HashState:                hashState,
			CreatedAt:                row.CreatedAt,
			ModifiedAt:               row.ModifiedAt,
			AccessedAt:               row.AccessedAt,
			ChangedAt:                row.ChangedAt,
			SICreatedAt:              row.SICreatedAt,
			SIModifiedAt:             row.SIModifiedAt,
			SIAccessedAt:             row.SIAccessedAt,
			SIChangedAt:              row.SIChangedAt,
			FNCreatedAt:              row.FNCreatedAt,
			FNModifiedAt:             row.FNModifiedAt,
			FNAccessedAt:             row.FNAccessedAt,
			FNChangedAt:              row.FNChangedAt,
			TimestampSource:          row.TimestampSource,
			CreatedTimestampSource:   row.CreatedTimestampSource,
			ModifiedTimestampSource:  row.ModifiedTimestampSource,
			AccessedTimestampSource:  row.AccessedTimestampSource,
			ChangedTimestampSource:   row.ChangedTimestampSource,
			RecordFlags:              row.RecordFlags,
			NameType:                 row.NameType,
			ParseWarnings:            row.ParseWarnings,
		})
	}

	return result
}

func buildPath(row RawEntry, byID map[string]RawEntry) (string, string, bool, bool) {
	if row.Name == "" && row.MFTEntry == row.ParentMFTEntry {
		return `\`, "", false, false
	}

	segments := make([]string, 0, 8)
	current := row
	visited := map[string]struct{}{}
	orphan := false
	reconstructionFailed := false

	for {
		key := keyFor(current.VolumeID, current.MFTEntry)
		if _, seen := visited[key]; seen {
			orphan = true
			reconstructionFailed = true
			break
		}
		visited[key] = struct{}{}

		if current.Name != "" {
			segments = append([]string{current.Name}, segments...)
		}

		if current.ParentMFTEntry == current.MFTEntry {
			break
		}

		parent, ok := byID[keyFor(current.VolumeID, current.ParentMFTEntry)]
		if !ok {
			orphan = true
			reconstructionFailed = true
			break
		}
		current = parent
	}

	fullPath := `\`
	if len(segments) > 0 {
		fullPath += strings.Join(segments, `\`)
	}
	parentPath := `\`
	if len(segments) > 1 {
		parentPath += strings.Join(segments[:len(segments)-1], `\`)
	} else if len(segments) <= 1 {
		parentPath = `\`
	}

	if fullPath == `\` {
		parentPath = ""
	}

	fullPath = normalizeExplorerRootAliasPath(fullPath)
	parentPath = normalizeExplorerParentPath(parentPath)

	return fullPath, parentPath, orphan, reconstructionFailed
}

func normalizeExplorerRootAliasPath(fullPath string) string {
	if !strings.HasPrefix(fullPath, `\.\`) {
		return fullPath
	}

	trimmed := strings.TrimPrefix(fullPath, `\.\`)
	firstSegment := trimmed
	if separator := strings.Index(firstSegment, `\`); separator >= 0 {
		firstSegment = firstSegment[:separator]
	}
	if firstSegment == "" || strings.HasPrefix(firstSegment, "$") {
		return fullPath
	}
	return `\` + trimmed
}

func normalizeExplorerParentPath(parentPath string) string {
	if parentPath == `\.` {
		return `\`
	}
	return normalizeExplorerRootAliasPath(parentPath)
}

var internalNTFSRootObjects = map[string]struct{}{
	"$AttrDef": {},
	"$BadClus": {},
	"$Bitmap":  {},
	"$Boot":    {},
	"$Extend":  {},
	"$LogFile": {},
	"$MFT":     {},
	"$MFTMirr": {},
	"$ObjId":   {},
	"$Quota":   {},
	"$Reparse": {},
	"$Secure":  {},
	"$UpCase":  {},
	"$UsnJrnl": {},
	"$Volume":  {},
}

func isInternalNTFSPath(fullPath string) bool {
	if fullPath == "" || fullPath == `\` {
		return false
	}
	if fullPath == `\.` {
		return true
	}

	trimmed := strings.TrimPrefix(fullPath, `\`)
	if strings.HasPrefix(trimmed, `.\`) {
		trimmed = strings.TrimPrefix(trimmed, `.\`)
	}
	firstSegment := trimmed
	if separator := strings.Index(firstSegment, `\`); separator >= 0 {
		firstSegment = firstSegment[:separator]
	}
	_, internal := internalNTFSRootObjects[firstSegment]
	return internal
}

func keyFor(volumeID string, entry int64) string {
	if volumeID == "" {
		return "entry:" + int64ToString(entry)
	}
	return volumeID + ":" + int64ToString(entry)
}

func fileExtension(name string, isDirectory bool) string {
	if isDirectory || name == "" {
		return ""
	}
	ext := path.Ext(name)
	return ext
}

func int64ToString(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	n := v
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + (n % 10))
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
