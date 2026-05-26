package models

import "windows-host-collector/forensics/filesystem"

// ScanEnvelope 主机采集顶层载荷
type ScanEnvelope struct {
	Version                string                          `json:"version"`
	Timestamp              string                          `json:"timestamp"`
	PlatformProfile        *PlatformProfile                `json:"platformProfile,omitempty"`
	StageDiagnostics       []StageDiagnostic               `json:"stageDiagnostics,omitempty"`
	System                 *HostIdentityInfo               `json:"system"`
	Resources              *ResourceUsageInfo              `json:"resources,omitempty"`
	Hardware               *HardwareInfo                   `json:"hardware,omitempty"`
	Processes              []*ProcessBasicInfo             `json:"processes"`
	ProcessDetails         map[int]*ProcessDetail          `json:"processDetails,omitempty"`
	FileIdentities         []FileIdentity                  `json:"fileIdentities,omitempty"`
	Network                NetworkData                     `json:"network"`
	Services               ServicesData                    `json:"services"`
	Users                  []LocalUserAccount              `json:"users,omitempty"`
	EnvVars                []EnvironmentVariable           `json:"envVars,omitempty"`
	Software               []InstalledSoftwareItem         `json:"software,omitempty"`
	Prefetch               []PrefetchEntry                 `json:"prefetch,omitempty"`
	BrowserHistory         []BrowserHistoryEntry           `json:"browserHistory,omitempty"`
	WebLogSources          []WebLogSource                  `json:"webLogSources,omitempty"`
	WebLogEntries          []WebLogEntry                   `json:"webLogEntries,omitempty"`
	UsbRecords             []UsbRecord                     `json:"usbRecords,omitempty"`
	OperationRecords       []OperationRecord               `json:"operationRecords,omitempty"`
	Registries             []RegistryValue                 `json:"registries,omitempty"`
	WindowsEventLogs       []WindowsLogItem                `json:"windowsEventLogs,omitempty"`
	ForensicVolumes        []filesystem.VolumeInfo         `json:"forensicVolumes,omitempty"`
	ForensicDirectoryNodes []filesystem.DirectoryNode      `json:"forensicDirectoryNodes,omitempty"`
	ForensicFileEntries    []filesystem.FileEntry          `json:"forensicFileEntries,omitempty"`
	ForensicTimelineEvents []filesystem.TimelineEvent      `json:"forensicTimelineEvents,omitempty"`
	ForensicDiagnostics    filesystem.CollectorDiagnostics `json:"forensicDiagnostics,omitempty"`
}

// QuickScanData 保留为兼容别名，上传载荷统一使用 ScanEnvelope。
type QuickScanData = ScanEnvelope

func (s *ScanEnvelope) UploadPayloadMap() map[string]any {
	if s == nil {
		return nil
	}
	payload := map[string]any{
		"version":                s.Version,
		"timestamp":              s.Timestamp,
		"platformProfile":        s.PlatformProfile,
		"stageDiagnostics":       s.StageDiagnostics,
		"system":                 s.System,
		"resources":              s.Resources,
		"hardware":               s.Hardware,
		"processes":              s.Processes,
		"processDetails":         s.ProcessDetails,
		"fileIdentities":         s.FileIdentities,
		"network":                s.Network,
		"services":               s.Services,
		"users":                  s.Users,
		"envVars":                s.EnvVars,
		"software":               s.Software,
		"prefetch":               s.Prefetch,
		"browserHistory":         s.BrowserHistory,
		"webLogSources":          s.WebLogSources,
		"webLogEntries":          s.WebLogEntries,
		"usbRecords":             s.UsbRecords,
		"operationRecords":       s.OperationRecords,
		"registries":             s.Registries,
		"windowsEventLogs":       s.WindowsEventLogs,
		"forensicVolumes":        s.ForensicVolumes,
		"forensicDirectoryNodes": s.ForensicDirectoryNodes,
		"forensicFileEntries":    s.ForensicFileEntries,
		"forensicTimelineEvents": s.ForensicTimelineEvents,
		"forensicDiagnostics":    s.ForensicDiagnostics,
	}
	for key, value := range payload {
		if isEmptyUploadPayloadValue(value) {
			delete(payload, key)
		}
	}
	return payload
}

func (s *ScanEnvelope) ReleaseCollectedData() {
	if s == nil {
		return
	}
	s.PlatformProfile = nil
	s.StageDiagnostics = nil
	s.System = nil
	s.Resources = nil
	s.Hardware = nil
	s.Processes = nil
	s.ProcessDetails = nil
	s.FileIdentities = nil
	s.Network = NetworkData{}
	s.Services = ServicesData{}
	s.Users = nil
	s.EnvVars = nil
	s.Software = nil
	s.Prefetch = nil
	s.BrowserHistory = nil
	s.WebLogSources = nil
	s.WebLogEntries = nil
	s.UsbRecords = nil
	s.OperationRecords = nil
	s.Registries = nil
	s.WindowsEventLogs = nil
	s.ForensicVolumes = nil
	s.ForensicDirectoryNodes = nil
	s.ForensicFileEntries = nil
	s.ForensicTimelineEvents = nil
	s.ForensicDiagnostics = filesystem.CollectorDiagnostics{}
}

func isEmptyUploadPayloadValue(value any) bool {
	switch typed := value.(type) {
	case nil:
		return true
	case string:
		return typed == ""
	case []StageDiagnostic:
		return len(typed) == 0
	case []*ProcessBasicInfo:
		return len(typed) == 0
	case map[int]*ProcessDetail:
		return len(typed) == 0
	case []FileIdentity:
		return len(typed) == 0
	case []LocalUserAccount:
		return len(typed) == 0
	case []EnvironmentVariable:
		return len(typed) == 0
	case []InstalledSoftwareItem:
		return len(typed) == 0
	case []PrefetchEntry:
		return len(typed) == 0
	case []BrowserHistoryEntry:
		return len(typed) == 0
	case []WebLogSource:
		return len(typed) == 0
	case []WebLogEntry:
		return len(typed) == 0
	case []UsbRecord:
		return len(typed) == 0
	case []OperationRecord:
		return len(typed) == 0
	case []RegistryValue:
		return len(typed) == 0
	case []WindowsLogItem:
		return len(typed) == 0
	case []filesystem.VolumeInfo:
		return len(typed) == 0
	case []filesystem.DirectoryNode:
		return len(typed) == 0
	case []filesystem.FileEntry:
		return len(typed) == 0
	case []filesystem.TimelineEvent:
		return len(typed) == 0
	case filesystem.CollectorDiagnostics:
		return typed.TotalRecordsRead == 0 &&
			typed.TotalParsedRecords == 0 &&
			typed.TotalEntriesEmitted == 0 &&
			typed.TotalFileEntriesEmitted == 0 &&
			typed.TotalDirectoryNodesEmitted == 0 &&
			typed.AllocatedEntryCount == 0 &&
			typed.DeletedEntryCount == 0 &&
			typed.OrphanEntryCount == 0 &&
			typed.InternalNTFSObjectCount == 0 &&
			typed.TimestampCoverageCreated == 0 &&
			typed.TimestampCoverageModified == 0 &&
			typed.TimestampCoverageAccessed == 0 &&
			typed.TimestampCoverageChanged == 0 &&
			typed.HashCoverageCount == 0 &&
			typed.PathReconstructionFailureCount == 0 &&
			typed.ReparsePointCount == 0 &&
			len(typed.SkippedVolumes) == 0
	default:
		return false
	}
}

// NetworkData 网络数据
type NetworkData struct {
	Sessions []NetworkSession `json:"sessions"`
	DnsCache []DnsCacheRecord `json:"dnsCache"`
	Shares   []NetworkShare   `json:"shares"`
	Hosts    []HostsEntry     `json:"hosts"`
}

// ServicesData 服务数据
type ServicesData struct {
	Services []ServiceItem `json:"services"`
	Drivers  []DriverItem  `json:"drivers"`
	Startups []StartupItem `json:"startups"`
}
