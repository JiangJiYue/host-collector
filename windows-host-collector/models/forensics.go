package models

// PrefetchEntry Prefetch 文件条目（对应前端 types.ts L405-414）
type PrefetchEntry struct {
	File        string `json:"file"`
	ProcessName string `json:"processName"`
	ProcessPath string `json:"processPath"`
	RunCount    int    `json:"runCount"`
	LastRunTime string `json:"lastRunTime"`
	Exists      bool   `json:"exists"`
	CreateTime  string `json:"createTime"`
	ModifyTime  string `json:"modifyTime"`
}

// BrowserHistoryEntry 浏览器历史条目（对应前端 types.ts L416-421）
type BrowserHistoryEntry struct {
	URL       string `json:"url"`
	Title     string `json:"title"`
	VisitTime string `json:"visitTime"`
	Browser   string `json:"browser"`
}

// WebLogSource Web 日志来源文件。
type WebLogSource struct {
	ID               string   `json:"id"`
	Path             string   `json:"path"`
	ServerType       string   `json:"serverType,omitempty"`
	Format           string   `json:"format,omitempty"`
	SiteName         string   `json:"siteName,omitempty"`
	Port             int      `json:"port,omitempty"`
	Protocol         string   `json:"protocol,omitempty"`
	SourceMethod     string   `json:"sourceMethod,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	Evidence         []string `json:"evidence,omitempty"`
	Size             int64    `json:"size,omitempty"`
	ModifiedAt       string   `json:"modifiedAt,omitempty"`
	Truncated        bool     `json:"truncated,omitempty"`
	TruncationReason string   `json:"truncationReason,omitempty"`
}

// WebLogEntry Web 访问日志解析后的基础记录。
type WebLogEntry struct {
	SourceID    string `json:"sourceId"`
	Timestamp   string `json:"timestamp,omitempty"`
	ClientIP    string `json:"clientIp,omitempty"`
	Method      string `json:"method,omitempty"`
	URI         string `json:"uri,omitempty"`
	Status      int    `json:"status,omitempty"`
	BytesSent   int64  `json:"bytesSent,omitempty"`
	UserAgent   string `json:"userAgent,omitempty"`
	Referer     string `json:"referer,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Host        string `json:"host,omitempty"`
	ServerType  string `json:"serverType,omitempty"`
	SiteName    string `json:"siteName,omitempty"`
	ProcessName string `json:"processName,omitempty"`
	ProcessPID  int    `json:"processPid,omitempty"`
}

// UsbRecord USB 设备记录（对应前端 types.ts L423-429）
type UsbRecord struct {
	Name         string `json:"name"`
	Vendor       string `json:"vendor"`
	InsertTime   string `json:"insertTime"`
	SerialNumber string `json:"serialNumber"`
	MountPoint   string `json:"mountPoint"`
}

// OperationRecord 操作记录（对应前端 types.ts L433-439）
type OperationRecord struct {
	Event         string `json:"event"` // open, proc
	OperationTime string `json:"operationTime"`
	File          string `json:"file"`
	FilePath      string `json:"filePath"`
	Source        string `json:"source"`
}
