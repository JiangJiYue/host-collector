package collector

import (
	"context"
	"strings"
	"sync"
	"time"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

// LogCollector Windows事件日志采集器
type LogCollector struct {
	progress    func(LogProgress)
	windowStart time.Time
}

var logCollectorWindowObserverForTesting struct {
	mu       sync.RWMutex
	observer func(time.Time)
}

// NewLogCollector 创建日志采集器
func NewLogCollector() *LogCollector {
	return &LogCollector{}
}

// WithProgress 注入事件日志采集进度回调
func (lc *LogCollector) WithProgress(fn func(LogProgress)) *LogCollector {
	lc.progress = fn
	return lc
}

func (lc *LogCollector) WithTimeWindow(start time.Time) *LogCollector {
	lc.windowStart = start
	if observer := logCollectorWindowObserverSnapshot(); observer != nil {
		observer(start)
	}
	return lc
}

func SetLogCollectorWindowObserverForTesting(observer func(time.Time)) func() {
	logCollectorWindowObserverForTesting.mu.Lock()
	previous := logCollectorWindowObserverForTesting.observer
	logCollectorWindowObserverForTesting.observer = observer
	logCollectorWindowObserverForTesting.mu.Unlock()

	return func() {
		logCollectorWindowObserverForTesting.mu.Lock()
		logCollectorWindowObserverForTesting.observer = previous
		logCollectorWindowObserverForTesting.mu.Unlock()
	}
}

func logCollectorWindowObserverSnapshot() func(time.Time) {
	logCollectorWindowObserverForTesting.mu.RLock()
	defer logCollectorWindowObserverForTesting.mu.RUnlock()
	return logCollectorWindowObserverForTesting.observer
}

// Name 返回采集器名称
func (lc *LogCollector) Name() string {
	return "log"
}

// LogCollectionResult 日志采集结果
type LogCollectionResult struct {
	WindowsEventLogs []models.WindowsLogItem `json:"windowsEventLogs"`
	Total            int                     `json:"total"`
}

// LogProgress 表示事件日志采集阶段进度
type LogProgress struct {
	Channel       string
	ChannelsDone  int
	ChannelsTotal int
	EventsRead    int
	TotalEvents   int
}

func (lc *LogCollector) report(progress LogProgress) {
	if lc.progress != nil {
		lc.progress(progress)
	}
}

func (lc *LogCollector) ReportForTesting(progress LogProgress) {
	lc.report(progress)
}

// Collect 采集Windows事件日志
func (lc *LogCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "事件日志采集中")

	logs := lc.collectPlatformLogs(ctx)

	utils.Info("Collector", "事件日志采集完成: %d条", len(logs))

	return &LogCollectionResult{
		WindowsEventLogs: logs,
		Total:            len(logs),
	}, nil
}

// convertLogLevel 转换Windows事件级别
func convertLogLevel(level int) string {
	switch level {
	case 1, 2:
		return "error"
	case 3:
		return "warning"
	default:
		return "info"
	}
}

// truncateString 截断字符串
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func eventWithinWindow(timestamp string, windowStart time.Time) bool {
	if windowStart.IsZero() {
		return true
	}
	parsed, ok := parseWindowTimestamp(timestamp)
	if !ok {
		return false
	}
	return !parsed.Before(windowStart)
}

func eventLogWindowDecision(windowStart time.Time, entry *models.WindowsLogItem) (keep bool, stop bool) {
	if entry == nil {
		return false, false
	}
	if windowStart.IsZero() {
		return true, false
	}
	entryTime, ok := parseWindowTimestamp(entry.Timestamp)
	if !ok {
		return false, false
	}
	if entryTime.Before(windowStart) {
		return false, true
	}
	return true, false
}

func parseWindowTimestamp(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err == nil {
		return parsed, true
	}
	parsed, err = time.Parse(time.RFC3339Nano, value)
	if err == nil {
		return parsed, true
	}
	return time.Time{}, false
}

// shouldKeepChannel 返回该通道是否应当纳入默认采集（供 Windows 平台调用）。
// 规则：
//   - 始终保留基础日志：System/Application/Security/Setup
//   - 保留常见的 Operational 通道（例如 PowerShell/Operational）
//   - 跳过名称上包含 Analytic/Debug/Trace/Tracing/Diagnostic/Performance 的通道，
//     因为这些在多数系统上默认未启用，查询会造成大量 ERROR_NOT_SUPPORTED。
func shouldKeepChannel(channel string) bool {
	lower := strings.ToLower(channel)

	// Always keep core logs
	if lower == "system" || lower == "application" || lower == "security" || lower == "setup" {
		return true
	}

	// Keep common operational channels
	if strings.Contains(lower, "/operational") || strings.Contains(lower, "powershell/operational") {
		return true
	}

	// Skip noisy/typically-disabled categories
	skipKeywords := []string{"/analytic", "/debug", "/trace", "/tracing", "diagnostic", "performance"}
	for _, kw := range skipKeywords {
		if strings.Contains(lower, kw) {
			return false
		}
	}

	// Otherwise keep; we’ll still gracefully handle per-channel errors
	return true
}
