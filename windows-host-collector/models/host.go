package models

// HostSummary 主机摘要信息（对应前端 types.ts L3-11）
type HostSummary struct {
	HostName    string    `json:"hostName"`
	Owner       string    `json:"owner"`
	OS          string    `json:"os"`
	RiskLevel   RiskLevel `json:"riskLevel"`
	CollectedAt string    `json:"collectedAt"`
	LastSeen    string    `json:"lastSeen"`
}

// HostIdentityInfo 主机身份信息
type HostIdentityInfo struct {
	Hostname        string               `json:"hostname"`
	NetworkAdapters []NetworkAdapterInfo `json:"networkAdapters,omitempty"`
	Username        string               `json:"username"`
	OSVersion       string               `json:"osVersion"`
	MajorVersion    string               `json:"majorVersion"`
	BuildType       string               `json:"buildType"`
	KernelVersion   string               `json:"kernelVersion"`
	InstallDate     string               `json:"installDate"`
	SystemDirectory string               `json:"systemDirectory"`
}

// DiskUsageInfo 单个磁盘使用信息
type DiskUsageInfo struct {
	Drive string  `json:"drive"`
	Usage float64 `json:"usage"`
	Used  float64 `json:"used"`
	Total float64 `json:"total"`
}

// ResourceUsageInfo 资源使用信息（对应前端 types.ts）
type ResourceUsageInfo struct {
	CPUUsage    float64         `json:"cpuUsage"`
	MemoryUsage float64         `json:"memoryUsage"`
	MemoryUsed  float64         `json:"memoryUsed"`
	MemoryTotal float64         `json:"memoryTotal"`
	Disks       []DiskUsageInfo `json:"disks"`
}

// HardwareInfo 硬件信息（对应前端 types.ts L35-40）
type HardwareInfo struct {
	Processor   string   `json:"processor"`
	MemorySize  string   `json:"memorySize"`
	BiosVersion string   `json:"biosVersion"`
	Disks       []string `json:"disks"`
}

// HostProfile 是系统采集器返回的内部聚合结构，统一结果载荷由 ScanEnvelope 表示。
type HostProfile struct {
	Identity  HostIdentityInfo  `json:"identity"`
	Resources ResourceUsageInfo `json:"resources"`
	Hardware  HardwareInfo      `json:"hardware"`
}
