package runner

import (
	"runtime"
	"time"

	"collector-shared/appcore"
	"collector-shared/orchestration"
	sharedUpload "collector-shared/upload"
	"linux-host-collector/internal/collectors/accounts"
	"linux-host-collector/internal/collectors/envvars"
	"linux-host-collector/internal/collectors/filesystem"
	"linux-host-collector/internal/collectors/history"
	"linux-host-collector/internal/collectors/host"
	"linux-host-collector/internal/collectors/logs"
	"linux-host-collector/internal/collectors/network"
	"linux-host-collector/internal/collectors/process"
	"linux-host-collector/internal/collectors/software"
	"linux-host-collector/internal/collectors/startup"
	"linux-host-collector/internal/collectors/timeline"
	"linux-host-collector/internal/collectors/weblogs"
)

func RunLocalScan(config Config) (Result, error) {
	if config.GoArch == "" {
		config.GoArch = runtime.GOARCH
	}
	if config.ScanID == "" {
		config.ScanID = appcore.FormatScanID(time.Now())
	}
	if config.CollectedAt.IsZero() {
		config.CollectedAt = time.Now()
	}

	scope := newScopeFilter(config.ScanScope)
	collectedAtTime := config.CollectedAt.UTC()
	collectedAt := collectedAtTime.Format(time.RFC3339)
	windowStart := scanWindowStart(collectedAtTime, config.WindowDays)
	progress := linuxProgressReporter{sink: config.StatusSink}
	progress.skippedDisabledStages(scope)

	sections := map[string]any{}
	if scope.allows("host") {
		progress.running("host", "主机信息", "主机信息采集中")
		hostResult := host.Collect(config.Root, config.GoArch)
		for key, value := range hostResult.Sections {
			sections[key] = value
		}
		progress.completed("host", "主机信息", "主机信息采集完成")
	}

	if scope.allows("users") {
		progress.running("users", "账号权限", "账号权限采集中")
		accountResult, err := accounts.Collect(config.Root)
		if err != nil {
			progress.failed("users", "账号权限", err.Error())
			return Result{}, err
		}
		sections["users"] = accountResult.Users
		sections["groups"] = accountResult.Groups
		progress.completed("users", "账号权限", "账号权限采集完成")
	}

	var processResult process.Result
	var hasProcessResult bool
	if scope.allows("process") || scope.allows("timeline") || scope.allows("web_logs") {
		progress.running("process", "进程", "进程采集中")
		result, err := process.Collect(config.Root)
		if err != nil {
			progress.failed("process", "进程", err.Error())
			return Result{}, err
		}
		processResult = result
		hasProcessResult = true
		if scope.allows("process") {
			sections["processes"] = processResult.Processes
			sections["processTree"] = processResult.ProcessTree
			if len(processResult.ProcessDetails) > 0 {
				sections["processDetails"] = processResult.ProcessDetails
			}
			if len(processResult.FileIdentities) > 0 {
				sections["fileIdentities"] = processResult.FileIdentities
			}
		}
		progress.completed("process", "进程", "进程采集完成")
	}

	var networkResult network.Result
	var hasNetworkResult bool
	if scope.allows("network") || scope.allows("timeline") || scope.allows("web_logs") {
		progress.running("network", "网络", "网络采集中")
		result, err := network.Collect(config.Root)
		if err != nil {
			progress.failed("network", "网络", err.Error())
			return Result{}, err
		}
		networkResult = result
		hasNetworkResult = true
		if scope.allows("network") {
			sections["network"] = networkResult
		}
		progress.completed("network", "网络", "网络采集完成")
	}

	var startupResult startup.Result
	var hasStartupResult bool
	if scope.allows("startup") || scope.allows("timeline") {
		progress.running("startup", "服务启动项", "服务启动项采集中")
		result, err := startup.Collect(config.Root)
		if err != nil {
			progress.failed("startup", "服务启动项", err.Error())
			return Result{}, err
		}
		startupResult = result
		hasStartupResult = true
		if scope.allows("startup") {
			sections["services"] = startupResult.Services
			sections["timers"] = startupResult.Timers
			sections["cronJobs"] = startupResult.CronJobs
			sections["persistenceItems"] = startupResult.PersistenceItems
		}
		progress.completed("startup", "服务启动项", "服务启动项采集完成")
	}

	var logResult logs.Result
	var hasLogResult bool
	if scope.allows("logs") || scope.allows("timeline") {
		progress.running("logs", "日志", "日志采集中")
		result, err := logs.Collect(config.Root)
		if err != nil {
			progress.failed("logs", "日志", err.Error())
			return Result{}, err
		}
		logResult = result
		applyLogWindow(&logResult, windowStart)
		hasLogResult = true
		if scope.allows("logs") {
			sections["linuxLogSources"] = logResult.Sources
			sections["linuxLogEvents"] = logResult.Events
		}
		progress.completed("logs", "日志", "日志采集完成")
	}

	if scope.allows("env_vars") {
		progress.running("env_vars", "环境变量", "环境变量采集中")
		envResult, err := envvars.Collect(config.Root)
		if err != nil {
			progress.failed("env_vars", "环境变量", err.Error())
			return Result{}, err
		}
		sections["envVars"] = envResult.Variables
		progress.completed("env_vars", "环境变量", "环境变量采集完成")
	}

	if scope.allows("software") {
		progress.running("software", "软件清单", "软件清单采集中")
		softwareResult, err := software.Collect(config.Root)
		if err != nil {
			progress.failed("software", "软件清单", err.Error())
			return Result{}, err
		}
		sections["software"] = softwareResult.Packages
		progress.completed("software", "软件清单", "软件清单采集完成")
	}

	if scope.allows("user_traces") {
		progress.running("user_traces", "用户痕迹", "用户痕迹采集中")
		historyResult, err := history.Collect(config.Root)
		if err != nil {
			progress.failed("user_traces", "用户痕迹", err.Error())
			return Result{}, err
		}
		applyHistoryWindow(&historyResult, windowStart)
		sections["operationRecords"] = historyResult.Records
		progress.completed("user_traces", "用户痕迹", "用户痕迹采集完成")
	}

	if scope.allows("web_logs") {
		progress.running("web_logs", "Web日志", "Web日志采集中")
		webLogResult, err := weblogs.Collect(weblogs.Config{
			Root:        config.Root,
			Processes:   processResult.Processes,
			Connections: networkResult.Connections,
		})
		if err != nil {
			progress.failed("web_logs", "Web日志", err.Error())
			return Result{}, err
		}
		applyWebLogWindow(&webLogResult, windowStart)
		sections["webLogSources"] = webLogResult.Sources
		sections["webLogEntries"] = webLogResult.Entries
		progress.completed("web_logs", "Web日志", "Web日志采集完成")
	}

	if scope.allows("file_system") {
		progress.running("file_system", "文件痕迹", "文件痕迹采集中")
		fileSystemResult, err := filesystem.Collect(config.Root)
		if err != nil {
			progress.failed("file_system", "文件痕迹", err.Error())
			return Result{}, err
		}
		sections["forensicVolumes"] = fileSystemResult.Volumes
		sections["forensicDirectoryNodes"] = fileSystemResult.DirectoryNodes
		sections["forensicFileEntries"] = fileSystemResult.FileEntries
		sections["forensicTimelineEvents"] = fileSystemResult.TimelineEvents
		if len(fileSystemResult.Diagnostics) > 0 {
			sections["forensicDiagnostics"] = fileSystemResult.Diagnostics
		}
		progress.completed("file_system", "文件痕迹", "文件痕迹采集完成")
	}

	if scope.allows("timeline") {
		progress.running("timeline", "时间线", "时间线生成中")
		inputs := timeline.Inputs{CollectedAt: collectedAt}
		if hasLogResult {
			inputs.LogEvents = logResult.Events
		}
		if hasNetworkResult {
			inputs.Network = networkResult
		}
		if hasStartupResult {
			inputs.PersistenceItems = startupResult.PersistenceItems
		}
		if hasProcessResult {
			inputs.Processes = processResult.Processes
		}
		sections["timelineEvents"] = timeline.Derive(inputs)
		progress.completed("timeline", "时间线", "时间线生成完成")
	}

	sections["platform"] = "linux"
	envelope := ScanEnvelope{
		ProtocolVersion: sharedUpload.ProtocolVersionUploadItemsV1,
		Platform:        "linux",
		Sections:        sections,
	}

	items, err := sharedUpload.PlanLinuxItems(sections, sharedUpload.Metadata{
		AgentID:     config.AgentID,
		ScanID:      config.ScanID,
		ScanType:    "local",
		CollectedAt: collectedAt,
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Envelope: envelope, UploadItems: items}, nil
}

func scanWindowStart(collectedAt time.Time, days int) time.Time {
	if days <= 0 {
		return time.Time{}
	}
	return collectedAt.AddDate(0, 0, -days)
}

func applyLogWindow(result *logs.Result, start time.Time) {
	if result == nil || start.IsZero() {
		return
	}
	filtered := make([]logs.Event, 0, len(result.Events))
	counts := map[string]int{}
	for _, event := range result.Events {
		if timestampInWindow(event.Timestamp, start) {
			filtered = append(filtered, event)
			counts[event.Source]++
		}
	}
	result.Events = filtered
	for index := range result.Sources {
		if result.Sources[index].Status != "available" {
			continue
		}
		result.Sources[index].EventCount = counts[result.Sources[index].Path]
		if result.Sources[index].EventCount == 0 {
			result.Sources[index].Reason = "no_matching_events_in_window"
		} else if result.Sources[index].Reason == "no_matching_events" || result.Sources[index].Reason == "no_matching_events_in_window" {
			result.Sources[index].Reason = ""
		}
	}
}

func applyHistoryWindow(result *history.Result, start time.Time) {
	if result == nil || start.IsZero() {
		return
	}
	filtered := make([]history.OperationRecord, 0, len(result.Records))
	for _, record := range result.Records {
		if timestampInWindow(record.OperationTime, start) {
			filtered = append(filtered, record)
		}
	}
	result.Records = filtered
}

func applyWebLogWindow(result *weblogs.Result, start time.Time) {
	if result == nil || start.IsZero() {
		return
	}
	filtered := make([]weblogs.Entry, 0, len(result.Entries))
	for _, entry := range result.Entries {
		if timestampInWindow(entry.Timestamp, start) {
			filtered = append(filtered, entry)
		}
	}
	result.Entries = filtered
}

func timestampInWindow(value string, start time.Time) bool {
	if start.IsZero() {
		return true
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		parsed, err = time.Parse(time.RFC3339Nano, value)
	}
	if err != nil {
		return false
	}
	return !parsed.Before(start)
}

type linuxProgressReporter struct {
	sink appcore.StatusSink
}

type linuxStageDefinition struct {
	key  string
	name string
}

var linuxStageDefinitions = []linuxStageDefinition{
	{key: "host", name: "主机信息"},
	{key: "users", name: "账号权限"},
	{key: "process", name: "进程"},
	{key: "network", name: "网络"},
	{key: "startup", name: "服务启动项"},
	{key: "logs", name: "日志"},
	{key: "env_vars", name: "环境变量"},
	{key: "software", name: "软件清单"},
	{key: "user_traces", name: "用户痕迹"},
	{key: "web_logs", name: "Web日志"},
	{key: "file_system", name: "文件系统"},
	{key: "timeline", name: "时间线"},
}

func (r linuxProgressReporter) running(stageKey string, stageName string, detail string) {
	r.emit(stageKey, stageName, appcore.StateRunning, detail)
}

func (r linuxProgressReporter) completed(stageKey string, stageName string, detail string) {
	r.emit(stageKey, stageName, appcore.StateCompleted, detail)
}

func (r linuxProgressReporter) failed(stageKey string, stageName string, detail string) {
	r.emit(stageKey, stageName, appcore.StateFailed, detail)
}

func (r linuxProgressReporter) skippedDisabledStages(scope scopeFilter) {
	for _, stage := range linuxStageDefinitions {
		if !scope.allows(stage.key) {
			r.emit(stage.key, stage.name, appcore.StateSkipped, stage.name+"阶段未启用")
		}
	}
}

func (r linuxProgressReporter) emit(stageKey string, stageName string, state appcore.StatusState, detail string) {
	if r.sink == nil {
		return
	}
	r.sink.EmitStatus(appcore.ScanProgressEvent(appcore.ScanProgressSummary{
		Step:      stageKey,
		StageKey:  stageKey,
		StageName: stageName,
		State:     state,
		Detail:    detail,
	}))
}

type scopeFilter struct {
	scope orchestration.ScopeSet
}

func newScopeFilter(scope []string) scopeFilter {
	return scopeFilter{scope: orchestration.NewScopeSet(scope)}
}

func (s scopeFilter) allows(item string) bool {
	return s.scope.Allows(item)
}
