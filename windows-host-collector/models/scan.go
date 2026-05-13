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

// QuickScanData 保留为兼容别名，本地结果载荷统一使用 ScanEnvelope。
type QuickScanData = ScanEnvelope

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
