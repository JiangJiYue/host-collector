package scanner

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"collector-shared/authpolicy"
	"windows-host-collector/collector"
	"windows-host-collector/internal/platform/capabilities"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

const comp = "HostScanner"
const stageStateRunning = "running"

type ScanProgress struct {
	Step       string `json:"step"`
	Current    int    `json:"current"`
	Total      int    `json:"total"`
	StageKey   string `json:"stage_key"`
	StageName  string `json:"stage_name"`
	StageState string `json:"stage_state"`
	Detail     string `json:"detail"`
}

var quickScanStages = []struct {
	Key  string
	Name string
}{
	{Key: "system", Name: "系统信息"},
	{Key: "file_system", Name: "文件系统"},
	{Key: "processes", Name: "进程"},
	{Key: "network", Name: "网络"},
	{Key: "services", Name: "服务"},
	{Key: "users", Name: "用户"},
	{Key: "software", Name: "软件"},
	{Key: "prefetch", Name: "Prefetch"},
	{Key: "browser_history", Name: "浏览器历史"},
	{Key: "web_logs", Name: "Web日志"},
	{Key: "usb", Name: "USB"},
	{Key: "registries", Name: "注册表"},
	{Key: "event_logs", Name: "事件日志"},
}

type QuickScanner struct {
	progress         func(ScanProgress)
	stageMu          sync.Mutex
	stageRows        map[string]models.ScanStageSummary
	stageDiagnostics []models.StageDiagnostic
	scope            map[string]struct{}
	policy           *authpolicy.Policy
	platform         *capabilities.Profile
}

var quickScanNowForTesting struct {
	mu  sync.RWMutex
	now func() time.Time
}

var quickScanProcessCollectForTesting struct {
	mu   sync.RWMutex
	hook func(context.Context, *collector.ProcessCollector) (*collector.ProcessCollectionResult, error)
}

var quickScanNetworkCollectForTesting struct {
	mu   sync.RWMutex
	hook func(context.Context, *collector.NetworkCollector) (*collector.NetworkCollectionResult, error)
}

var quickScanBrowserHistoryCollectForTesting struct {
	mu   sync.RWMutex
	hook func(context.Context, *collector.BrowserHistoryCollector) (*collector.BrowserHistoryCollectionResult, error)
}

var quickScanSoftwareCollectForTesting struct {
	mu   sync.RWMutex
	hook func(context.Context, *collector.SoftwareCollector) (*collector.SoftwareCollectionResult, error)
}

var quickScanForensicFileSystemCollectForTesting struct {
	mu   sync.RWMutex
	hook func(context.Context, *collector.ForensicFileSystemCollector) (*collector.ForensicFileSystemResult, error)
}

var quickScanLogCollectForTesting struct {
	mu   sync.RWMutex
	hook func(context.Context, *collector.LogCollector) (*collector.LogCollectionResult, error)
}

func setQuickScanProcessCollectHookForTesting(hook func(context.Context, *collector.ProcessCollector) (*collector.ProcessCollectionResult, error)) func() {
	quickScanProcessCollectForTesting.mu.Lock()
	previous := quickScanProcessCollectForTesting.hook
	quickScanProcessCollectForTesting.hook = hook
	quickScanProcessCollectForTesting.mu.Unlock()

	return func() {
		quickScanProcessCollectForTesting.mu.Lock()
		quickScanProcessCollectForTesting.hook = previous
		quickScanProcessCollectForTesting.mu.Unlock()
	}
}

func quickScanProcessCollectHookSnapshot() func(context.Context, *collector.ProcessCollector) (*collector.ProcessCollectionResult, error) {
	quickScanProcessCollectForTesting.mu.RLock()
	defer quickScanProcessCollectForTesting.mu.RUnlock()
	return quickScanProcessCollectForTesting.hook
}

func setQuickScanNetworkCollectHookForTesting(hook func(context.Context, *collector.NetworkCollector) (*collector.NetworkCollectionResult, error)) func() {
	quickScanNetworkCollectForTesting.mu.Lock()
	previous := quickScanNetworkCollectForTesting.hook
	quickScanNetworkCollectForTesting.hook = hook
	quickScanNetworkCollectForTesting.mu.Unlock()

	return func() {
		quickScanNetworkCollectForTesting.mu.Lock()
		quickScanNetworkCollectForTesting.hook = previous
		quickScanNetworkCollectForTesting.mu.Unlock()
	}
}

func quickScanNetworkCollectHookSnapshot() func(context.Context, *collector.NetworkCollector) (*collector.NetworkCollectionResult, error) {
	quickScanNetworkCollectForTesting.mu.RLock()
	defer quickScanNetworkCollectForTesting.mu.RUnlock()
	return quickScanNetworkCollectForTesting.hook
}

func setQuickScanBrowserHistoryCollectHookForTesting(hook func(context.Context, *collector.BrowserHistoryCollector) (*collector.BrowserHistoryCollectionResult, error)) func() {
	quickScanBrowserHistoryCollectForTesting.mu.Lock()
	previous := quickScanBrowserHistoryCollectForTesting.hook
	quickScanBrowserHistoryCollectForTesting.hook = hook
	quickScanBrowserHistoryCollectForTesting.mu.Unlock()

	return func() {
		quickScanBrowserHistoryCollectForTesting.mu.Lock()
		quickScanBrowserHistoryCollectForTesting.hook = previous
		quickScanBrowserHistoryCollectForTesting.mu.Unlock()
	}
}

func quickScanBrowserHistoryCollectHookSnapshot() func(context.Context, *collector.BrowserHistoryCollector) (*collector.BrowserHistoryCollectionResult, error) {
	quickScanBrowserHistoryCollectForTesting.mu.RLock()
	defer quickScanBrowserHistoryCollectForTesting.mu.RUnlock()
	return quickScanBrowserHistoryCollectForTesting.hook
}

func setQuickScanSoftwareCollectHookForTesting(hook func(context.Context, *collector.SoftwareCollector) (*collector.SoftwareCollectionResult, error)) func() {
	quickScanSoftwareCollectForTesting.mu.Lock()
	previous := quickScanSoftwareCollectForTesting.hook
	quickScanSoftwareCollectForTesting.hook = hook
	quickScanSoftwareCollectForTesting.mu.Unlock()

	return func() {
		quickScanSoftwareCollectForTesting.mu.Lock()
		quickScanSoftwareCollectForTesting.hook = previous
		quickScanSoftwareCollectForTesting.mu.Unlock()
	}
}

func quickScanSoftwareCollectHookSnapshot() func(context.Context, *collector.SoftwareCollector) (*collector.SoftwareCollectionResult, error) {
	quickScanSoftwareCollectForTesting.mu.RLock()
	defer quickScanSoftwareCollectForTesting.mu.RUnlock()
	return quickScanSoftwareCollectForTesting.hook
}

func setQuickScanForensicFileSystemCollectHookForTesting(hook func(context.Context, *collector.ForensicFileSystemCollector) (*collector.ForensicFileSystemResult, error)) func() {
	quickScanForensicFileSystemCollectForTesting.mu.Lock()
	previous := quickScanForensicFileSystemCollectForTesting.hook
	quickScanForensicFileSystemCollectForTesting.hook = hook
	quickScanForensicFileSystemCollectForTesting.mu.Unlock()

	return func() {
		quickScanForensicFileSystemCollectForTesting.mu.Lock()
		quickScanForensicFileSystemCollectForTesting.hook = previous
		quickScanForensicFileSystemCollectForTesting.mu.Unlock()
	}
}

func quickScanForensicFileSystemCollectHookSnapshot() func(context.Context, *collector.ForensicFileSystemCollector) (*collector.ForensicFileSystemResult, error) {
	quickScanForensicFileSystemCollectForTesting.mu.RLock()
	defer quickScanForensicFileSystemCollectForTesting.mu.RUnlock()
	return quickScanForensicFileSystemCollectForTesting.hook
}

func setQuickScanLogCollectHookForTesting(hook func(context.Context, *collector.LogCollector) (*collector.LogCollectionResult, error)) func() {
	quickScanLogCollectForTesting.mu.Lock()
	previous := quickScanLogCollectForTesting.hook
	quickScanLogCollectForTesting.hook = hook
	quickScanLogCollectForTesting.mu.Unlock()

	return func() {
		quickScanLogCollectForTesting.mu.Lock()
		quickScanLogCollectForTesting.hook = previous
		quickScanLogCollectForTesting.mu.Unlock()
	}
}

func quickScanLogCollectHookSnapshot() func(context.Context, *collector.LogCollector) (*collector.LogCollectionResult, error) {
	quickScanLogCollectForTesting.mu.RLock()
	defer quickScanLogCollectForTesting.mu.RUnlock()
	return quickScanLogCollectForTesting.hook
}

func NewQuickScanner() *QuickScanner {
	return &QuickScanner{
		stageRows: map[string]models.ScanStageSummary{},
	}
}

func (qs *QuickScanner) WithProgress(fn func(ScanProgress)) *QuickScanner {
	qs.progress = fn
	return qs
}

func (qs *QuickScanner) WithScope(modules []string) *QuickScanner {
	qs.scope = normalizeScanScopeModules(modules)
	return qs
}

func (qs *QuickScanner) WithPolicy(policy *authpolicy.Policy) *QuickScanner {
	qs.policy = policy
	return qs
}

func (qs *QuickScanner) WithPlatformProfile(profile capabilities.Profile) *QuickScanner {
	qs.platform = &profile
	return qs
}

func (qs *QuickScanner) shouldRunStage(stageKey string) bool {
	return quickStagePlan.ShouldRunStage(scopeSetFromMap(qs.scope), stageKey)
}

func (qs *QuickScanner) stageCapabilityDecision(stageKey string, profile capabilities.Profile) stageRunDecision {
	if !qs.shouldRunStage(stageKey) {
		return stageRunDecision{Run: false}
	}
	return stageCapabilityDecision(stageKey, profile)
}

func (qs *QuickScanner) report(progress ScanProgress) {
	if qs.progress != nil {
		qs.progress(progress)
	}
}

func (qs *QuickScanner) reportStage(stageKey, stageState, detail string) {
	current, stageName := quickScanStageInfo(stageKey)
	step := detail
	if step == "" {
		step = stageName
	}
	qs.stageMu.Lock()
	qs.stageRows[stageKey] = models.ScanStageSummary{
		Name:   stageName,
		State:  stageState,
		Detail: detail,
	}
	qs.stageMu.Unlock()
	qs.report(ScanProgress{
		Step:       step,
		Current:    current,
		Total:      len(quickScanStages),
		StageKey:   stageKey,
		StageName:  stageName,
		StageState: stageState,
		Detail:     detail,
	})
}

func (qs *QuickScanner) reportStageDecision(stageKey string, decision stageRunDecision) {
	qs.reportStage(stageKey, string(models.StageSkipped), decision.Detail)
	if decision.ReasonCode == "" {
		return
	}
	qs.stageMu.Lock()
	qs.stageDiagnostics = append(qs.stageDiagnostics, stageDiagnostic(stageKey, decision))
	qs.stageMu.Unlock()
}

func (qs *QuickScanner) stageDiagnosticsSnapshot() []models.StageDiagnostic {
	qs.stageMu.Lock()
	defer qs.stageMu.Unlock()
	diagnostics := make([]models.StageDiagnostic, len(qs.stageDiagnostics))
	copy(diagnostics, qs.stageDiagnostics)
	return diagnostics
}

func quickScanStageInfo(stageKey string) (int, string) {
	for index, stage := range quickScanStages {
		if stage.Key == stageKey {
			return index + 1, stage.Name
		}
	}
	return 0, stageKey
}

func (qs *QuickScanner) Scan(ctx context.Context) (*models.ScanEnvelope, error) {
	utils.Info(comp, "主机采集开始: collectors=13")
	startTime := quickScanNow()
	windowStart := qs.policyWindowStart(startTime)
	execProfile := DeriveExecutionProfile()
	platformProfile := qs.effectivePlatformProfile()
	utils.Info(
		comp,
		"主机采集调度配置: profile=%s workers=%d allow_deep_registry=%t platform=%s support=%s build_family=%s",
		execProfile.Name,
		execProfile.ProcessDetailWorkers,
		execProfile.AllowDeepRegistry,
		platformProfile.Platform,
		platformProfile.SupportLevel,
		platformProfile.BuildFamily,
	)
	data := &models.ScanEnvelope{
		Version:         "1.0.0",
		Timestamp:       startTime.Format(time.RFC3339),
		PlatformProfile: platformProfileModel(platformProfile),
	}

	done := make(chan bool, 11)
	processesDone := make(chan struct{})
	networkDone := make(chan struct{})
	softwareDone := make(chan struct{})

	// 1. 系统信息
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "系统信息采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("system") {
			qs.reportStage("system", string(models.StageSkipped), "系统信息阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("system", platformProfile); !decision.Run {
			qs.reportStageDecision("system", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: system")
		qs.reportStage("system", stageStateRunning, "系统信息采集中")
		systemCollector := collector.NewSystemCollector()
		result, err := systemCollector.Collect(ctx)
		if err != nil {
			utils.LogError(comp, "系统信息采集失败: %v", err)
		}
		if result != nil {
			if profile, ok := result.(*models.HostProfile); ok {
				data.System = &profile.Identity
				data.Resources = &profile.Resources
				data.Hardware = &profile.Hardware
				utils.Info(comp, "系统信息采集成功: hostname=%s", profile.Identity.Hostname)
			} else {
				utils.LogError(comp, "系统信息类型断言失败, type=%T", result)
			}
		} else {
			utils.LogError(comp, "系统信息采集返回 nil")
		}
		qs.reportStage("system", string(models.StageCompleted), "系统信息采集完成")
		utils.Info(comp, "主机采集阶段完成: system")
	}()

	// 1.5 文件系统取证
	go func() {
		defer func() {
			done <- true
		}()
		if !qs.shouldRunStage("file_system") {
			qs.reportStage("file_system", string(models.StageSkipped), "文件系统阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("file_system", platformProfile); !decision.Run {
			qs.reportStageDecision("file_system", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: file_system")
		qs.reportStage("file_system", stageStateRunning, "文件系统取证采集中")
		fileSystemCollector := collector.NewForensicFileSystemCollector()
		var (
			fileSystemResult *collector.ForensicFileSystemResult
			err              error
		)
		if hook := quickScanForensicFileSystemCollectHookSnapshot(); hook != nil {
			fileSystemResult, err = hook(ctx, fileSystemCollector)
		} else {
			var result interface{}
			result, err = fileSystemCollector.Collect(ctx)
			if result != nil {
				var ok bool
				fileSystemResult, ok = result.(*collector.ForensicFileSystemResult)
				if !ok {
					utils.LogError(comp, "文件系统取证类型断言失败, type=%T", result)
				}
			}
		}
		if err != nil {
			utils.LogError(comp, "文件系统取证采集失败: %v", err)
		}
		if fileSystemResult != nil {
			data.ForensicVolumes = fileSystemResult.Volumes
			data.ForensicDirectoryNodes = fileSystemResult.DirectoryNodes
			data.ForensicFileEntries = fileSystemResult.FileEntries
			data.ForensicTimelineEvents = fileSystemResult.TimelineEvents
			data.ForensicDiagnostics = fileSystemResult.Diagnostics
			utils.Info(comp, "文件系统取证采集成功: %d卷, %d目录, %d文件, %d时间线",
				len(fileSystemResult.Volumes),
				len(fileSystemResult.DirectoryNodes),
				len(fileSystemResult.FileEntries),
				len(fileSystemResult.TimelineEvents),
			)
		} else {
			utils.LogError(comp, "文件系统取证采集返回 nil")
		}
		qs.reportStage("file_system", string(models.StageCompleted), "文件系统取证采集完成")
		utils.Info(comp, "主机采集阶段完成: file_system")
	}()

	// 2. 进程列表
	go func() {
		defer func() {
			close(processesDone)
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "进程采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("processes") {
			qs.reportStage("processes", string(models.StageSkipped), "进程阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("processes", platformProfile); !decision.Run {
			qs.reportStageDecision("processes", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: processes")
		qs.reportStage("processes", stageStateRunning, "进程采集中")
		processCollector := collector.NewProcessCollector(true).
			WithDetailWorkers(execProfile.ProcessDetailWorkers).
			WithProgress(func(progress collector.ProcessProgress) {
				step := fmt.Sprintf("进程详情采集中: PID=%d %s (%d/%d)", progress.PID, progress.ProcessName, progress.Processed, progress.Total)
				qs.reportStage("processes", stageStateRunning, step)
			})
		var (
			procResult *collector.ProcessCollectionResult
			err        error
		)
		if hook := quickScanProcessCollectHookSnapshot(); hook != nil {
			procResult, err = hook(ctx, processCollector)
		} else {
			var result interface{}
			result, err = processCollector.Collect(ctx)
			if result != nil {
				var ok bool
				procResult, ok = result.(*collector.ProcessCollectionResult)
				if !ok {
					utils.LogError(comp, "进程类型断言失败, type=%T", result)
				}
			}
		}
		if err != nil {
			utils.LogError(comp, "进程采集失败: %v", err)
		}
		if procResult != nil {
			data.Processes = procResult.Processes
			data.ProcessDetails = procResult.ProcessDetails
			data.FileIdentities = procResult.FileIdentities
			utils.Info(comp, "进程采集成功: %d 个进程, %d 个详情, %d 个文件身份", len(procResult.Processes), len(procResult.ProcessDetails), len(procResult.FileIdentities))
		} else {
			utils.LogError(comp, "进程采集返回 nil")
		}
		qs.reportStage("processes", string(models.StageCompleted), "进程采集完成")
		utils.Info(comp, "主机采集阶段完成: processes")
	}()

	// 3. 网络连接
	go func() {
		defer func() {
			close(networkDone)
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "网络采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("network") {
			qs.reportStage("network", string(models.StageSkipped), "网络阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("network", platformProfile); !decision.Run {
			qs.reportStageDecision("network", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: network")
		qs.reportStage("network", stageStateRunning, "网络采集中")
		networkCollector := collector.NewNetworkCollector()
		var (
			netResult *collector.NetworkCollectionResult
			err       error
		)
		if hook := quickScanNetworkCollectHookSnapshot(); hook != nil {
			netResult, err = hook(ctx, networkCollector)
		} else {
			var result interface{}
			result, err = networkCollector.Collect(ctx)
			if result != nil {
				var ok bool
				netResult, ok = result.(*collector.NetworkCollectionResult)
				if !ok {
					utils.LogError(comp, "网络类型断言失败, type=%T", result)
				}
			}
		}
		if err != nil {
			utils.LogError(comp, "网络采集失败: %v", err)
		}
		if netResult != nil {
			data.Network.Sessions = netResult.Sessions
			data.Network.DnsCache = netResult.DNS
			data.Network.Shares = netResult.Shares
			data.Network.Hosts = netResult.Hosts
			utils.Info(comp, "网络采集成功: %d连接, %dDNS, %d共享, %dHosts",
				len(netResult.Sessions), len(netResult.DNS), len(netResult.Shares), len(netResult.Hosts))
		} else {
			utils.LogError(comp, "网络采集返回 nil")
		}
		qs.reportStage("network", string(models.StageCompleted), "网络采集完成")
		utils.Info(comp, "主机采集阶段完成: network")
	}()

	// 4. 服务启动项
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "服务采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("services") {
			qs.reportStage("services", string(models.StageSkipped), "服务阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("services", platformProfile); !decision.Run {
			qs.reportStageDecision("services", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: services")
		qs.reportStage("services", stageStateRunning, "服务采集中")
		serviceCollector := collector.NewServiceCollector()
		result, err := serviceCollector.Collect(ctx)
		if err != nil {
			utils.LogError(comp, "服务采集失败: %v", err)
		}
		if result != nil {
			if svcResult, ok := result.(*collector.ServiceCollectionResult); ok {
				data.Services.Services = svcResult.Services
				data.Services.Drivers = svcResult.Drivers
				data.Services.Startups = svcResult.Startups
				utils.Info(comp, "服务采集成功: %d服务, %d驱动, %d启动项",
					len(svcResult.Services), len(svcResult.Drivers), len(svcResult.Startups))
			} else {
				utils.LogError(comp, "服务类型断言失败, type=%T", result)
			}
		} else {
			utils.LogError(comp, "服务采集返回 nil")
		}
		qs.reportStage("services", string(models.StageCompleted), "服务采集完成")
		utils.Info(comp, "主机采集阶段完成: services")
	}()

	// 5. 用户账户和环境变量
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "用户采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("users") {
			qs.reportStage("users", string(models.StageSkipped), "用户阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("users", platformProfile); !decision.Run {
			qs.reportStageDecision("users", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: users")
		qs.reportStage("users", stageStateRunning, "用户采集中")
		userCollector := collector.NewUserCollector()
		result, err := userCollector.Collect(ctx)
		if err != nil {
			utils.LogError(comp, "用户采集失败: %v", err)
		}
		if result != nil {
			if userResult, ok := result.(*collector.UserCollectionResult); ok {
				data.Users = userResult.Users
				data.EnvVars = userResult.EnvVars
				utils.Info(comp, "用户采集成功: %d用户, %d环境变量", len(userResult.Users), len(userResult.EnvVars))
			} else {
				utils.LogError(comp, "用户类型断言失败, type=%T", result)
			}
		} else {
			utils.LogError(comp, "用户采集返回 nil")
		}
		qs.reportStage("users", string(models.StageCompleted), "用户采集完成")
		utils.Info(comp, "主机采集阶段完成: users")
	}()

	// 6. 已安装软件
	go func() {
		defer func() {
			close(softwareDone)
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "软件采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("software") {
			qs.reportStage("software", string(models.StageSkipped), "软件阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("software", platformProfile); !decision.Run {
			qs.reportStageDecision("software", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: software")
		qs.reportStage("software", stageStateRunning, "软件采集中")
		softwareCollector := collector.NewSoftwareCollector()
		var (
			swResult *collector.SoftwareCollectionResult
			err      error
		)
		if hook := quickScanSoftwareCollectHookSnapshot(); hook != nil {
			swResult, err = hook(ctx, softwareCollector)
		} else {
			var result interface{}
			result, err = softwareCollector.Collect(ctx)
			if result != nil {
				var ok bool
				swResult, ok = result.(*collector.SoftwareCollectionResult)
				if !ok {
					utils.LogError(comp, "软件类型断言失败, type=%T", result)
				}
			}
		}
		if err != nil {
			utils.LogError(comp, "软件采集失败: %v", err)
		}
		if swResult != nil {
			data.Software = swResult.Software
			utils.Info(comp, "软件采集成功: %d个", len(swResult.Software))
		} else {
			utils.LogError(comp, "软件采集返回 nil")
		}
		qs.reportStage("software", string(models.StageCompleted), "软件采集完成")
		utils.Info(comp, "主机采集阶段完成: software")
	}()

	// 7. Prefetch
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "Prefetch采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("prefetch") {
			qs.reportStage("prefetch", string(models.StageSkipped), "Prefetch 阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("prefetch", platformProfile); !decision.Run {
			qs.reportStageDecision("prefetch", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: prefetch")
		qs.reportStage("prefetch", stageStateRunning, "Prefetch 采集中")
		prefetchCollector := collector.NewPrefetchCollector()
		result, err := prefetchCollector.Collect(ctx)
		if err != nil {
			utils.LogError(comp, "Prefetch采集失败: %v", err)
		}
		if result != nil {
			if pfResult, ok := result.(*collector.PrefetchCollectionResult); ok {
				data.Prefetch = pfResult.Entries
				utils.Info(comp, "Prefetch采集成功: %d个", len(pfResult.Entries))
			} else {
				utils.LogError(comp, "Prefetch类型断言失败, type=%T", result)
			}
		} else {
			utils.LogError(comp, "Prefetch采集返回 nil")
		}
		qs.reportStage("prefetch", string(models.StageCompleted), "Prefetch 采集完成")
		utils.Info(comp, "主机采集阶段完成: prefetch")
	}()

	// 8. 浏览器历史
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "浏览器历史 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("browser_history") {
			qs.reportStage("browser_history", string(models.StageSkipped), "浏览器历史阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("browser_history", platformProfile); !decision.Run {
			qs.reportStageDecision("browser_history", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: browser_history")
		qs.reportStage("browser_history", stageStateRunning, "浏览器历史采集中")
		browserCollector := collector.NewBrowserHistoryCollector()
		var (
			bhResult *collector.BrowserHistoryCollectionResult
			err      error
		)
		if hook := quickScanBrowserHistoryCollectHookSnapshot(); hook != nil {
			bhResult, err = hook(ctx, browserCollector)
		} else {
			var result interface{}
			result, err = browserCollector.Collect(ctx)
			if result != nil {
				var ok bool
				bhResult, ok = result.(*collector.BrowserHistoryCollectionResult)
				if !ok {
					utils.LogError(comp, "浏览器历史类型断言失败, type=%T", result)
				}
			}
		}
		if err != nil {
			utils.LogError(comp, "浏览器历史采集失败: %v", err)
		}
		if bhResult != nil {
			data.BrowserHistory = bhResult.Entries
			utils.Info(comp, "浏览器历史采集成功: %d条", len(bhResult.Entries))
		} else {
			utils.LogError(comp, "浏览器历史采集返回 nil")
		}
		qs.reportStage("browser_history", string(models.StageCompleted), "浏览器历史采集完成")
		utils.Info(comp, "主机采集阶段完成: browser_history")
	}()

	// 9. Web日志
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "Web日志采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("web_logs") {
			qs.reportStage("web_logs", string(models.StageSkipped), "Web日志阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("web_logs", platformProfile); !decision.Run {
			qs.reportStageDecision("web_logs", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: web_logs")
		qs.reportStage("web_logs", stageStateRunning, "Web日志采集中")
		<-processesDone
		<-networkDone
		<-softwareDone
		webLogCollector := collector.NewWebLogCollector().WithDiscoveryContext(collector.WebLogDiscoveryContext{
			Processes:       data.Processes,
			ProcessDetails:  data.ProcessDetails,
			NetworkSessions: data.Network.Sessions,
			Software:        data.Software,
		}).WithTimeWindow(windowStart)
		result, err := webLogCollector.Collect(ctx)
		if err != nil {
			utils.LogError(comp, "Web日志采集失败: %v", err)
		}
		if result != nil {
			if webResult, ok := result.(*collector.WebLogCollectionResult); ok {
				data.WebLogSources = webResult.Sources
				data.WebLogEntries = webResult.Entries
				utils.Info(comp, "Web日志采集成功: %d来源, %d条记录", len(webResult.Sources), len(webResult.Entries))
			} else {
				utils.LogError(comp, "Web日志类型断言失败, type=%T", result)
			}
		} else {
			utils.LogError(comp, "Web日志采集返回 nil")
		}
		qs.reportStage("web_logs", string(models.StageCompleted), "Web日志采集完成")
		utils.Info(comp, "主机采集阶段完成: web_logs")
	}()

	// 10. USB 记录
	go func() {
		defer func() {
			if r := recover(); r != nil {
				buf := make([]byte, 4096)
				n := runtime.Stack(buf, false)
				utils.LogError(comp, "USB采集 panic: %v\nStack: %s", r, buf[:n])
			}
			done <- true
		}()
		if !qs.shouldRunStage("usb") {
			qs.reportStage("usb", string(models.StageSkipped), "USB 阶段未启用")
			return
		}
		if decision := qs.stageCapabilityDecision("usb", platformProfile); !decision.Run {
			qs.reportStageDecision("usb", decision)
			return
		}
		utils.Info(comp, "主机采集阶段开始: usb")
		qs.reportStage("usb", stageStateRunning, "USB 记录采集中")
		usbCollector := collector.NewUsbCollector()
		result, err := usbCollector.Collect(ctx)
		if err != nil {
			utils.LogError(comp, "USB采集失败: %v", err)
		}
		if result != nil {
			if usbResult, ok := result.(*collector.UsbCollectionResult); ok {
				data.UsbRecords = usbResult.Records
				utils.Info(comp, "USB采集成功: %d条", len(usbResult.Records))
			} else {
				utils.LogError(comp, "USB类型断言失败, type=%T", result)
			}
		} else {
			utils.LogError(comp, "USB采集返回 nil")
		}
		qs.reportStage("usb", string(models.StageCompleted), "USB 记录采集完成")
		utils.Info(comp, "主机采集阶段完成: usb")
	}()

	// 等待前 11 个核心阶段完成，再启动后续重型阶段，避免并发写入扫描结果。
	for i := 0; i < 11; i++ {
		<-done
	}

	heavyStages := 0

	if qs.shouldRunStage("registries") && execProfile.AllowDeepRegistry {
		if decision := qs.stageCapabilityDecision("registries", platformProfile); !decision.Run {
			qs.reportStageDecision("registries", decision)
		} else {
			heavyStages++
			go func() {
				defer func() {
					if r := recover(); r != nil {
						buf := make([]byte, 4096)
						n := runtime.Stack(buf, false)
						utils.LogError(comp, "注册表采集 panic: %v\nStack: %s", r, buf[:n])
					}
					done <- true
				}()
				utils.Info(comp, "主机采集阶段开始: registries")
				qs.reportStage("registries", stageStateRunning, "注册表采集中")
				registryCollector := collector.NewRegistryCollector().WithProgress(func(progress collector.RegistryProgress) {
					qs.reportStage("registries", stageStateRunning, fmt.Sprintf("注册表采集中: %s (%d/%d)", progress.RootName, progress.RootsDone+1, progress.RootsTotal))
				})
				result, err := registryCollector.Collect(ctx)
				if err != nil {
					utils.LogError(comp, "注册表采集失败: %v", err)
				}
				if result != nil {
					if regResult, ok := result.(*collector.RegistryCollectionResult); ok {
						data.Registries = regResult.Values
						utils.Info(comp, "注册表采集完成: %d个值", len(regResult.Values))
					} else {
						utils.LogError(comp, "注册表类型断言失败, type=%T", result)
					}
				} else {
					utils.LogError(comp, "注册表采集返回 nil")
				}
				qs.reportStage("registries", string(models.StageCompleted), "注册表采集完成")
				utils.Info(comp, "主机采集阶段完成: registries")
			}()
		}
	} else {
		qs.reportStage("registries", string(models.StageSkipped), "注册表阶段未启用")
	}

	if qs.shouldRunStage("event_logs") {
		if decision := qs.stageCapabilityDecision("event_logs", platformProfile); !decision.Run {
			qs.reportStageDecision("event_logs", decision)
		} else {
			heavyStages++
			logCollector := collector.NewLogCollector().WithTimeWindow(windowStart)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						buf := make([]byte, 4096)
						n := runtime.Stack(buf, false)
						utils.LogError(comp, "事件日志采集 panic: %v\nStack: %s", r, buf[:n])
					}
					done <- true
				}()
				utils.Info(comp, "主机采集阶段开始: event_logs")
				qs.reportStage("event_logs", stageStateRunning, "事件日志采集中")
				var (
					logResult *collector.LogCollectionResult
					err       error
				)
				if hook := quickScanLogCollectHookSnapshot(); hook != nil {
					logResult, err = hook(ctx, logCollector)
				} else {
					var result interface{}
					result, err = logCollector.Collect(ctx)
					if result != nil {
						var ok bool
						logResult, ok = result.(*collector.LogCollectionResult)
						if !ok {
							utils.LogError(comp, "事件日志类型断言失败, type=%T", result)
						}
					}
				}
				if err != nil {
					utils.LogError(comp, "事件日志采集失败: %v", err)
				}
				if logResult != nil {
					data.WindowsEventLogs = logResult.WindowsEventLogs
					utils.Info(comp, "事件日志采集成功: %d条", len(logResult.WindowsEventLogs))
				} else {
					utils.LogError(comp, "事件日志采集返回 nil")
				}
				qs.reportStage("event_logs", string(models.StageCompleted), "事件日志采集完成")
				utils.Info(comp, "主机采集阶段完成: event_logs")
			}()
		}
	} else {
		qs.reportStage("event_logs", string(models.StageSkipped), "事件日志阶段未启用")
	}

	for i := 0; i < heavyStages; i++ {
		<-done
	}

	if len(data.Network.DnsCache) > 0 || len(data.BrowserHistory) > 0 {
		data.Network.DnsCache = collector.EnrichDNSCacheRecords(ctx, data.Network.DnsCache, data.BrowserHistory)
		utils.Info(comp, "DNS缓存解析增强完成: %d条", len(data.Network.DnsCache))
	}

	utils.Info(comp, "主机采集全部完成")
	data.StageDiagnostics = qs.stageDiagnosticsSnapshot()
	applyScopeToQuickScanData(data, quickScannerScopeList(qs.scope))
	return data, nil
}

func (qs *QuickScanner) policyWindowStart(now time.Time) time.Time {
	policy := qs.policy
	if policy == nil || policy.LogWindowDays <= 0 {
		return time.Time{}
	}
	return now.AddDate(0, 0, -policy.LogWindowDays)
}

func quickScanNow() time.Time {
	quickScanNowForTesting.mu.RLock()
	now := quickScanNowForTesting.now
	quickScanNowForTesting.mu.RUnlock()
	if now != nil {
		return now()
	}
	return time.Now()
}

func (qs *QuickScanner) effectivePlatformProfile() capabilities.Profile {
	if qs.platform != nil {
		return *qs.platform
	}
	return defaultScannerPlatformProfile()
}

func setQuickScanNowForTesting(now time.Time) func() {
	quickScanNowForTesting.mu.Lock()
	previous := quickScanNowForTesting.now
	quickScanNowForTesting.now = func() time.Time { return now }
	quickScanNowForTesting.mu.Unlock()

	return func() {
		quickScanNowForTesting.mu.Lock()
		quickScanNowForTesting.now = previous
		quickScanNowForTesting.mu.Unlock()
	}
}

func quickScannerScopeList(scope map[string]struct{}) []string {
	if len(scope) == 0 {
		return nil
	}
	result := make([]string, 0, len(scope))
	for module := range scope {
		result = append(result, module)
	}
	return result
}
