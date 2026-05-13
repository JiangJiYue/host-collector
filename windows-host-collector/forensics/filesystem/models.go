package filesystem

type VolumeInfo struct {
	VolumeID             string `json:"volumeId"`
	DevicePath           string `json:"devicePath"`
	DriveLetter          string `json:"driveLetter,omitempty"`
	FileSystem           string `json:"filesystem,omitempty"`
	FilesystemProbeError string `json:"filesystemProbeError,omitempty"`
	SerialNumber         string `json:"serialNumber,omitempty"`
	BytesPerSector       uint16 `json:"bytesPerSector,omitempty"`
	SectorsPerCluster    uint8  `json:"sectorsPerCluster,omitempty"`
	ClusterSize          int64  `json:"clusterSize,omitempty"`
	MFTStartLCN          int64  `json:"mftStartLcn,omitempty"`
	FileRecordSize       int64  `json:"fileRecordSize,omitempty"`
}

type DirectoryNode struct {
	NodeID         string `json:"nodeId"`
	VolumeID       string `json:"volumeId"`
	MFTEntry       int64  `json:"mftEntry"`
	MFTSequence    int64  `json:"mftSequence,omitempty"`
	ParentMFTEntry int64  `json:"parentMftEntry"`
	Path           string `json:"path"`
	ParentPath     string `json:"parentPath,omitempty"`
	Name           string `json:"name"`
	IsOrphan       bool   `json:"isOrphan,omitempty"`
}

type FileEntry struct {
	EntryID                  string   `json:"entryId"`
	VolumeID                 string   `json:"volumeId"`
	MFTEntry                 int64    `json:"mftEntry"`
	MFTSequence              int64    `json:"mftSequence"`
	ParentMFTEntry           int64    `json:"parentMftEntry"`
	Path                     string   `json:"path"`
	ParentPath               string   `json:"parentPath"`
	Name                     string   `json:"name"`
	Extension                string   `json:"extension,omitempty"`
	IsDirectory              bool     `json:"isDirectory"`
	IsDeleted                bool     `json:"isDeleted"`
	IsAllocated              bool     `json:"isAllocated"`
	IsOrphan                 bool     `json:"isOrphan"`
	IsInternalNTFSObject     bool     `json:"isInternalNtfsObject,omitempty"`
	PathReconstructionFailed bool     `json:"pathReconstructionFailed,omitempty"`
	Size                     int64    `json:"size"`
	AllocatedSize            int64    `json:"allocatedSize"`
	MimeType                 string   `json:"mimeType,omitempty"`
	MD5                      string   `json:"md5,omitempty"`
	SHA1                     string   `json:"sha1,omitempty"`
	SHA256                   string   `json:"sha256,omitempty"`
	HashState                string   `json:"hashState"`
	CreatedAt                string   `json:"createdAt,omitempty"`
	ModifiedAt               string   `json:"modifiedAt,omitempty"`
	AccessedAt               string   `json:"accessedAt,omitempty"`
	ChangedAt                string   `json:"changedAt,omitempty"`
	SICreatedAt              string   `json:"siCreatedAt,omitempty"`
	SIModifiedAt             string   `json:"siModifiedAt,omitempty"`
	SIAccessedAt             string   `json:"siAccessedAt,omitempty"`
	SIChangedAt              string   `json:"siChangedAt,omitempty"`
	FNCreatedAt              string   `json:"fnCreatedAt,omitempty"`
	FNModifiedAt             string   `json:"fnModifiedAt,omitempty"`
	FNAccessedAt             string   `json:"fnAccessedAt,omitempty"`
	FNChangedAt              string   `json:"fnChangedAt,omitempty"`
	TimestampSource          string   `json:"timestampSource,omitempty"`
	CreatedTimestampSource   string   `json:"createdTimestampSource,omitempty"`
	ModifiedTimestampSource  string   `json:"modifiedTimestampSource,omitempty"`
	AccessedTimestampSource  string   `json:"accessedTimestampSource,omitempty"`
	ChangedTimestampSource   string   `json:"changedTimestampSource,omitempty"`
	RecordFlags              []string `json:"recordFlags,omitempty"`
	NameType                 string   `json:"nameType,omitempty"`
	ReparseTarget            string   `json:"reparseTarget,omitempty"`
	ADSCount                 int      `json:"adsCount,omitempty"`
	ParseWarnings            []string `json:"parseWarnings,omitempty"`
}

type TimelineEvent struct {
	EventID   string `json:"eventId"`
	VolumeID  string `json:"volumeId"`
	EntryID   string `json:"entryId"`
	Path      string `json:"path"`
	EventType string `json:"eventType"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source,omitempty"`
}

type CollectorDiagnostics struct {
	TotalRecordsRead               int                    `json:"totalRecordsRead,omitempty"`
	TotalParsedRecords             int                    `json:"totalParsedRecords"`
	TotalEntriesEmitted            int                    `json:"totalEntriesEmitted"`
	TotalFileEntriesEmitted        int                    `json:"totalFileEntriesEmitted"`
	TotalDirectoryNodesEmitted     int                    `json:"totalDirectoryNodesEmitted"`
	AllocatedEntryCount            int                    `json:"allocatedEntryCount"`
	DeletedEntryCount              int                    `json:"deletedEntryCount"`
	OrphanEntryCount               int                    `json:"orphanEntryCount"`
	InternalNTFSObjectCount        int                    `json:"internalNtfsObjectCount"`
	TimestampCoverageCreated       int                    `json:"timestampCoverageCreated"`
	TimestampCoverageModified      int                    `json:"timestampCoverageModified"`
	TimestampCoverageAccessed      int                    `json:"timestampCoverageAccessed"`
	TimestampCoverageChanged       int                    `json:"timestampCoverageChanged"`
	HashCoverageCount              int                    `json:"hashCoverageCount"`
	PathReconstructionFailureCount int                    `json:"pathReconstructionFailureCount"`
	ReparsePointCount              int                    `json:"reparsePointCount"`
	SkippedVolumes                 []VolumeSkipDiagnostic `json:"skippedVolumes,omitempty"`
}

type VolumeSkipDiagnostic struct {
	VolumeID    string `json:"volumeId,omitempty"`
	DriveLetter string `json:"driveLetter,omitempty"`
	FileSystem  string `json:"filesystem,omitempty"`
	ReasonCode  string `json:"reasonCode"`
	Evidence    string `json:"evidence,omitempty"`
}

type RawEntry struct {
	VolumeID                string
	MFTEntry                int64
	MFTSequence             int64
	ParentMFTEntry          int64
	Name                    string
	IsDirectory             bool
	IsDeleted               bool
	IsAllocated             bool
	Size                    int64
	AllocatedSize           int64
	HashState               string
	TimestampSource         string
	CreatedTimestampSource  string
	ModifiedTimestampSource string
	AccessedTimestampSource string
	ChangedTimestampSource  string
	CreatedAt               string
	ModifiedAt              string
	AccessedAt              string
	ChangedAt               string
	SICreatedAt             string
	SIModifiedAt            string
	SIAccessedAt            string
	SIChangedAt             string
	FNCreatedAt             string
	FNModifiedAt            string
	FNAccessedAt            string
	FNChangedAt             string
	RecordFlags             []string
	NameType                string
	ParseWarnings           []string
}
