package localbundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"

	"collector-shared/runmode"
)

type Bundle struct {
	Metadata runmode.OutputMetadata
	LocalCLI any
	Sections map[string]any
}

type Manifest struct {
	Metadata runmode.OutputMetadata `json:"metadata"`
	LocalCLI any                    `json:"local_cli,omitempty"`
	Files    Files                  `json:"files"`
	Domains  map[string]DomainEntry `json:"domains"`
}

type Files struct {
	Sections map[string]string `json:"sections"`
}

type DomainEntry struct {
	Key         string `json:"key"`
	Title       string `json:"title"`
	Description string `json:"description"`
	SectionFile string `json:"section_file,omitempty"`
	ItemCount   int    `json:"item_count"`
	OSSIncluded bool   `json:"oss_included"`
	Reason      string `json:"reason,omitempty"`
}

type domainSpec struct {
	Key         string
	Title       string
	Description string
	Sections    []string
	OSSIncluded bool
	Reason      string
	EmitOnScope bool
}

var domainSpecs = []domainSpec{
	{Key: "host", Title: "主机", Description: "系统、资源、硬件和平台画像", Sections: []string{"system", "resources", "hardware", "platformFacts"}, OSSIncluded: true},
	{Key: "process", Title: "进程", Description: "进程列表、进程详情、进程树和文件身份", Sections: []string{"processes", "processDetails", "processTree", "fileIdentities"}, OSSIncluded: true},
	{Key: "network", Title: "网络", Description: "连接、监听、DNS 和网络接口证据", Sections: []string{"network"}, OSSIncluded: true},
	{Key: "logs", Title: "日志", Description: "Linux 日志、Windows 事件日志和日志源状态", Sections: []string{"linuxLogSources", "linuxLogEvents", "windowsEventLogs"}, OSSIncluded: true},
	{Key: "users", Title: "用户", Description: "账号、用户组、权限和登录痕迹", Sections: []string{"users", "groups", "privilegeEvidence"}, OSSIncluded: true},
	{Key: "startup", Title: "启动项", Description: "服务、计划任务、定时器和持久化项", Sections: []string{"services", "timers", "cronJobs", "persistenceItems"}, OSSIncluded: true},
	{Key: "software", Title: "软件", Description: "已安装软件和包管理记录", Sections: []string{"software"}, OSSIncluded: true},
	{Key: "timeline", Title: "时间线", Description: "跨域派生的溯源时间线事件", Sections: []string{"timelineEvents"}, OSSIncluded: true},
	{Key: "user_traces", Title: "用户痕迹", Description: "Prefetch、浏览器历史、USB 记录和 shell history 等用户行为痕迹", Sections: []string{"prefetch", "browserHistory", "usbRecords", "operationRecords"}, OSSIncluded: true, EmitOnScope: true},
	{Key: "web_logs", Title: "Web 日志", Description: "Web 服务日志源、访问记录和运行时关联", Sections: []string{"webLogSources", "webLogEntries"}, OSSIncluded: true},
	{Key: "registry", Title: "注册表", Description: "Windows 注册表键值、持久化和系统配置证据", Sections: []string{"registries"}, OSSIncluded: true, EmitOnScope: true},
	{Key: "file_system", Title: "文件系统", Description: "文件系统卷、目录、文件元数据和时间线证据", Sections: []string{"forensicVolumes", "forensicDirectoryNodes", "forensicFileEntries", "forensicTimelineEvents", "forensicDiagnostics"}, OSSIncluded: true, EmitOnScope: true},
}

func Write(dir string, bundle Bundle) error {
	if err := os.MkdirAll(filepath.Join(dir, "sections"), 0700); err != nil {
		return err
	}

	manifest := Manifest{
		Metadata: bundle.Metadata,
		LocalCLI: bundle.LocalCLI,
		Files: Files{
			Sections: map[string]string{},
		},
		Domains: map[string]DomainEntry{},
	}

	for _, spec := range domainSpecs {
		payload := map[string]any{}
		if scopeAllowsDomain(bundle.Metadata.CollectionScope, spec.Key) {
			payload = domainPayload(bundle.Sections, spec.Sections)
			if spec.EmitOnScope && len(payload) == 0 && scopeWasExplicit(bundle.Metadata.CollectionScope) {
				payload = emptyDomainPayload(spec.Sections)
			}
		}
		entry := DomainEntry{
			Key:         spec.Key,
			Title:       spec.Title,
			Description: spec.Description,
			OSSIncluded: spec.OSSIncluded,
			Reason:      spec.Reason,
		}
		if spec.OSSIncluded && len(payload) > 0 {
			relPath := filepath.Join("sections", spec.Key+".json")
			if err := writeJSON(filepath.Join(dir, relPath), payload); err != nil {
				return err
			}
			entry.SectionFile = relPath
			entry.ItemCount = itemCount(payload)
			manifest.Files.Sections[spec.Key] = relPath
		}
		manifest.Domains[spec.Key] = entry
	}

	return writeJSON(filepath.Join(dir, "manifest.json"), manifest)
}

func scopeAllowsDomain(scope []string, domain string) bool {
	if len(scope) == 0 {
		return false
	}
	for _, item := range scope {
		if item == domain {
			return true
		}
	}
	return false
}

func scopeWasExplicit(scope []string) bool {
	return len(scope) > 0
}

func domainPayload(sections map[string]any, names []string) map[string]any {
	payload := map[string]any{}
	for _, name := range names {
		if value, ok := sections[name]; ok && !isEmptyValue(value) {
			payload[name] = value
		}
	}
	return payload
}

func emptyDomainPayload(names []string) map[string]any {
	payload := make(map[string]any, len(names))
	for _, name := range names {
		if name == "forensicDiagnostics" {
			payload[name] = map[string]any{}
			continue
		}
		payload[name] = []any{}
	}
	return payload
}

func isEmptyValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	for reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Interface {
		if reflected.IsNil() {
			return true
		}
		reflected = reflected.Elem()
	}
	switch reflected.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
		return reflected.Len() == 0
	case reflect.Struct:
		return reflected.IsZero()
	default:
		return false
	}
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func itemCount(value any) int {
	if value == nil {
		return 0
	}
	if mapped, ok := value.(map[string]any); ok {
		total := 0
		for _, child := range mapped {
			childCount := itemCount(child)
			if childCount == 0 {
				childCount = 1
			}
			total += childCount
		}
		return total
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Array, reflect.Slice, reflect.Map:
		return reflected.Len()
	default:
		return 1
	}
}
