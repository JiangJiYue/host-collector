package models

// ServiceItem Windows服务项（对应前端 types.ts L274-284）
type ServiceItem struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	DisplayName  string   `json:"displayName"`
	Account      *string  `json:"account,omitempty"`
	Path         *string  `json:"path,omitempty"`
	Description  *string  `json:"description,omitempty"`
	DllPath      *string  `json:"dllPath,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// DriverItem 驱动项（对应前端 types.ts L286-293）
type DriverItem struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	DisplayName  string   `json:"displayName"`
	Path         *string  `json:"path,omitempty"`
	Description  *string  `json:"description,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// StartupSafetyStatus 启动项安全状态
type StartupSafetyStatus string

const (
	StartupSystem   StartupSafetyStatus = "system"
	StartupSigned   StartupSafetyStatus = "signed"
	StartupUnsigned StartupSafetyStatus = "unsigned"
)

// StartupRunStatus 启动项运行状态
type StartupRunStatus string

const (
	StartupRunning StartupRunStatus = "running"
	StartupStopped StartupRunStatus = "stopped"
)

// StartupItem 启动项（对应前端 types.ts L249-259）
type StartupItem struct {
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	SafetyStatus StartupSafetyStatus `json:"safetyStatus"`
	Description  *string             `json:"description,omitempty"`
	Company      *string             `json:"company,omitempty"`
	RunStatus    StartupRunStatus    `json:"runStatus"`
	Path         *string             `json:"path,omitempty"`
	Category     string              `json:"category"`
}

// InstalledSoftwareItem 已安装软件（对应前端 types.ts L417-424）
type InstalledSoftwareItem struct {
	Name            string `json:"name"`
	Publisher       string `json:"publisher"`
	InstallDate     string `json:"installDate"`
	Size            string `json:"size"`
	Version         string `json:"version"`
	InstallLocation string `json:"installLocation"`
}

// WindowsLogLevel Windows日志级别
type WindowsLogLevel string

const (
	LogLevelCritical    WindowsLogLevel = "critical"
	LogLevelError       WindowsLogLevel = "error"
	LogLevelWarning     WindowsLogLevel = "warning"
	LogLevelInformation WindowsLogLevel = "info"
)

// WindowsLogItem Windows事件日志（对应前端 types.ts L344-355）
type WindowsLogItem struct {
	ID               string            `json:"id"`
	LogType          string            `json:"logType"` // security, system, application, powershell, other
	Level            string            `json:"level"`   // info, warning, error
	EventID          int               `json:"eventId"`
	Summary          string            `json:"summary"`
	Timestamp        string            `json:"timestamp"`
	DetailsXml       string            `json:"detailsXml"`
	ProcessName      *string           `json:"processName,omitempty"`
	LogonType        *int              `json:"logonType,omitempty"`
	HostApplication  *string           `json:"hostApplication,omitempty"`
	EventData        map[string]string `json:"eventData,omitempty"`
	NormalizedFields map[string]string `json:"normalizedFields,omitempty"`
	Keywords         []string          `json:"keywords,omitempty"`
}
