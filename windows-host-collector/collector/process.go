package collector

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"collector-shared/orchestration"
	"windows-host-collector/models"
	"windows-host-collector/utils"

	"github.com/shirou/gopsutil/v3/process"
)

const comp = "ProcessCollector"
const defaultProcessDetailTimeout = 8 * time.Second

type ProcessCollector struct {
	includeDetails  bool
	progressEvery   int
	detailWorkers   int
	progress        func(ProcessProgress)
	fileIdentities  *FileIdentityCollector
	windowSnapshot  map[int32][]models.ProcessWindow
	detailTimeout   time.Duration
	detailCollector func(context.Context, *models.ProcessBasicInfo) (*models.ProcessDetail, processDetailCounts, error)
}

func NewProcessCollector(includeDetails bool) *ProcessCollector {
	return &ProcessCollector{
		includeDetails: includeDetails,
		progressEvery:  10,
		detailWorkers:  1,
		detailTimeout:  defaultProcessDetailTimeout,
		fileIdentities: NewFileIdentityCollector(),
	}
}

func (pc *ProcessCollector) Name() string {
	return "process"
}

func (pc *ProcessCollector) WithProgress(fn func(ProcessProgress)) *ProcessCollector {
	pc.progress = fn
	return pc
}

func (pc *ProcessCollector) WithDetailWorkers(workers int) *ProcessCollector {
	pc.detailWorkers = workers
	return pc
}

func (pc *ProcessCollector) WithDetailTimeout(timeout time.Duration) *ProcessCollector {
	pc.detailTimeout = timeout
	return pc
}

func (pc *ProcessCollector) report(progress ProcessProgress) {
	if pc.progress != nil {
		pc.progress(progress)
	}
}

func (pc *ProcessCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info(comp, "开始采集进程信息...")

	processes, err := pc.collectProcessList(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to collect process list: %w", err)
	}

	utils.Info(comp, "采集到 %d 个进程", len(processes))

	var details map[int]*models.ProcessDetail
	if pc.includeDetails {
		details = pc.collectProcessDetails(ctx, processes)
		utils.Info(comp, "采集了 %d 个进程的详细信息", len(details))
	}

	return &ProcessCollectionResult{
		Processes:      processes,
		ProcessDetails: details,
		FileIdentities: pc.fileIdentityCollector().Identities(),
		Total:          len(processes),
	}, nil
}

type ProcessCollectionResult struct {
	Processes      []*models.ProcessBasicInfo    `json:"processes"`
	ProcessDetails map[int]*models.ProcessDetail `json:"processDetails,omitempty"`
	FileIdentities []models.FileIdentity         `json:"fileIdentities,omitempty"`
	Total          int                           `json:"total"`
}

func (pc *ProcessCollector) collectProcessList(ctx context.Context) ([]*models.ProcessBasicInfo, error) {
	fileIdentities := pc.fileIdentityCollector()

	pids, err := process.Pids()
	if err != nil {
		utils.LogError(comp, "获取进程列表失败: %v，使用模拟数据", err)
		return pc.getMockProcessList(), nil
	}

	result := make([]*models.ProcessBasicInfo, 0, len(pids))
	for _, pid := range pids {
		p, err := process.NewProcess(pid)
		if err != nil {
			continue
		}

		name, _ := p.Name()
		cmdline, _ := p.Cmdline()
		exe, _ := p.Exe()
		createTime, _ := p.CreateTime()
		username, _ := p.Username()
		numThreads, _ := p.NumThreads()
		ppid, _ := p.Ppid()

		var cmdPtr, exePtr, userPtr *string
		if cmdline != "" {
			cmdPtr = &cmdline
		}
		if exe != "" {
			exePtr = &exe
		}
		if username != "" {
			userPtr = &username
		}

		info := &models.ProcessBasicInfo{
			ProcessName: name,
			PID:         int(pid),
			CommandLine: cmdPtr,
			ImagePath:   exePtr,
			User:        userPtr,
			ParentPID:   utils.IntPtr(int(ppid)),
			ThreadCount: utils.IntPtr(int(numThreads)),
		}

		if createTime > 0 {
			createdAt := utils.FormatTimeUnix(createTime)
			info.CreatedAt = &createdAt
		}

		info.SessionID = pc.getSessionID(p)
		info.BasePriority = pc.getBasePriority(p)
		info.HandleCount = pc.getHandleCount(p)
		info.Is64Bit = pc.getIs64Bit(exe)
		domain, _ := pc.getProcessDomain(username)
		if domain != "" {
			info.Domain = &domain
		}
		info.BaseAddress = pc.getBaseAddress(p)

		if ppid > 0 {
			parent, err := process.NewProcess(ppid)
			if err == nil {
				parentName, _ := parent.Name()
				parentCmdline, _ := parent.Cmdline()
				parentExe, _ := parent.Exe()
				if parentName != "" {
					info.ParentName = &parentName
				}
				if parentCmdline != "" {
					info.ParentCommandLine = &parentCmdline
				}
				if parentExe != "" {
					info.ParentPath = &parentExe
					fileIdentities.CollectFile(parentExe, []string{"process.parent_image"})
				}
			}
		}

		if exe != "" {
			identity := fileIdentities.CollectFile(exe, []string{"process.image"})
			pc.attachProcessFileIdentity(info, identity)
			if identity.MD5 != "" {
				info.MD5 = &identity.MD5
			}
			signals := classifySystemProcessMasquerade(info.ProcessName, identity.NormalizedPath, info.ParentName, info.CommandLine)
			if len(signals) > 0 {
				info.MasqueradeSignals = signals
				if severity := maxSignalSeverity(signals); severity != "" {
					info.MasqueradeRiskLevel = &severity
				}
			}
		}

		result = append(result, info)
	}

	return result, nil
}

func (pc *ProcessCollector) collectProcessDetails(ctx context.Context, processes []*models.ProcessBasicInfo) map[int]*models.ProcessDetail {
	workers := pc.detailWorkerCount()
	details := make(map[int]*models.ProcessDetail, len(processes))
	state := newProcessDetailProgressState(len(processes), pc.progressEvery)
	utils.Info(comp, "进程详情采集开始: total=%d workers=%d", len(processes), workers)

	pc.windowSnapshot = nil
	if snapshot, err := snapshotProcessWindows(); err == nil {
		pc.windowSnapshot = snapshot
		utils.Info(comp, "进程窗口快照采集成功: processes=%d", len(snapshot))
	} else {
		utils.Warn(comp, "进程窗口快照采集失败，回退为无窗口详情: %v", err)
	}

	var mu sync.Mutex
	ioCount, memCount, threadCount, moduleCount, windowCount, handleCount, connCount := 0, 0, 0, 0, 0, 0, 0

	orchestration.RunBounded(ctx, workers, processes, func(ctx context.Context, p *models.ProcessBasicInfo) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		detail, counts, err := pc.collectProcessDetailWithTimeout(ctx, p)
		if err != nil {
			utils.Warn(comp, "PID %d: 无法打开进程: %v", p.PID, err)
		}
		var (
			processed    int
			total        int
			shouldReport bool
		)

		mu.Lock()
		if detail != nil {
			details[p.PID] = detail
			ioCount += counts.IO
			memCount += counts.Memory
			threadCount += counts.Threads
			moduleCount += counts.Modules
			windowCount += counts.Windows
			handleCount += counts.Handles
			connCount += counts.Connections
		}
		state.Processed++
		processed = state.Processed
		total = state.Total
		if state.ShouldReport() {
			state.MarkReported()
			shouldReport = true
		}
		mu.Unlock()

		if shouldReport {
			utils.Info(comp, "进程详情采集中: PID=%d name=%s (%d/%d)", p.PID, p.ProcessName, processed, total)
			pc.report(ProcessProgress{
				PID:         p.PID,
				ProcessName: p.ProcessName,
				Processed:   processed,
				Total:       total,
			})
		}
	})

	utils.Info(comp, "进程详情采集统计: IO=%d, 内存=%d, 线程=%d, 模块=%d, 窗口=%d, 句柄=%d, 连接=%d",
		ioCount, memCount, threadCount, moduleCount, windowCount, handleCount, connCount)

	return details
}

type processDetailCounts struct {
	IO          int
	Memory      int
	Threads     int
	Modules     int
	Windows     int
	Handles     int
	Connections int
}

func (pc *ProcessCollector) detailWorkerCount() int {
	if pc.detailWorkers <= 0 {
		return 1
	}
	return pc.detailWorkers
}

func (pc *ProcessCollector) processDetailTimeout() time.Duration {
	if pc.detailTimeout <= 0 {
		return defaultProcessDetailTimeout
	}
	return pc.detailTimeout
}

func (pc *ProcessCollector) collectProcessDetailWithTimeout(ctx context.Context, p *models.ProcessBasicInfo) (*models.ProcessDetail, processDetailCounts, error) {
	collector := pc.detailCollector
	if collector == nil {
		collector = pc.collectProcessDetail
	}
	timeout := pc.processDetailTimeout()
	detailCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		detail *models.ProcessDetail
		counts processDetailCounts
		err    error
	}
	done := make(chan result, 1)
	go func() {
		detail, counts, err := collector(detailCtx, p)
		done <- result{detail: detail, counts: counts, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, processDetailCounts{}, ctx.Err()
	case <-detailCtx.Done():
		utils.Warn(comp, "PID %d (%s): 进程详情采集超时，已跳过该进程详情", p.PID, p.ProcessName)
		return nil, processDetailCounts{}, detailCtx.Err()
	case result := <-done:
		return result.detail, result.counts, result.err
	}
}

func (pc *ProcessCollector) collectProcessDetail(ctx context.Context, p *models.ProcessBasicInfo) (*models.ProcessDetail, processDetailCounts, error) {
	select {
	case <-ctx.Done():
		return nil, processDetailCounts{}, ctx.Err()
	default:
	}

	proc, err := process.NewProcess(int32(p.PID))
	if err != nil {
		return nil, processDetailCounts{}, err
	}

	detail := &models.ProcessDetail{
		BasicInfo:          p,
		MemoryBlocks:       []models.ProcessMemoryBlock{},
		IOStats:            models.ProcessIOStats{},
		Modules:            []models.ProcessModule{},
		ModulesTotal:       0,
		Threads:            []models.ProcessThread{},
		Windows:            []models.ProcessWindow{},
		NetworkConnections: []models.ProcessNetworkConnection{},
		Handles:            []models.ProcessHandle{},
	}
	counts := processDetailCounts{}

	ioCounters, err := proc.IOCounters()
	if err == nil && ioCounters != nil {
		detail.IOStats = models.ProcessIOStats{
			ReadCount:          int64(ioCounters.ReadCount),
			WriteCount:         int64(ioCounters.WriteCount),
			OtherCount:         0,
			ReadTransferCount:  int64(ioCounters.ReadBytes),
			WriteTransferCount: int64(ioCounters.WriteBytes),
			OtherTransferCount: 0,
		}
		counts.IO = 1
		utils.Debug(comp, "PID %d (%s): IO 采集成功", p.PID, p.ProcessName)
	} else {
		utils.Debug(comp, "PID %d (%s): IO 采集跳过: %v", p.PID, p.ProcessName, err)
	}

	memInfo, err := proc.MemoryInfo()
	if err == nil && memInfo != nil {
		detail.MemoryBlocks = []models.ProcessMemoryBlock{
			{
				ID:          fmt.Sprintf("mem-%d-0", p.PID),
				BaseAddress: fmt.Sprintf("0x%x", memInfo.RSS),
				Size:        utils.FormatBytes(memInfo.VMS),
				Type:        "Private",
				Protection:  "RW",
				CanRead:     true,
				CanWrite:    true,
				CanExecute:  false,
				Guarded:     false,
			},
		}
		counts.Memory = 1
		utils.Debug(comp, "PID %d (%s): 内存采集成功", p.PID, p.ProcessName)
	} else {
		utils.Debug(comp, "PID %d (%s): 内存采集跳过: %v", p.PID, p.ProcessName, err)
	}

	threads, err := collectProcessThreads(int32(p.PID))
	if err == nil {
		detail.Threads = threads
		counts.Threads = len(threads)
		utils.Debug(comp, "PID %d (%s): 线程采集成功, %d 个线程", p.PID, p.ProcessName, len(threads))
	} else {
		utils.Debug(comp, "PID %d (%s): 线程采集失败: %v", p.PID, p.ProcessName, err)
	}

	mods, err := collectProcessModules(int32(p.PID))
	if err == nil {
		fileIdentities := pc.fileIdentityCollector()
		for i := range mods {
			if mods[i].Path == "" {
				continue
			}
			identity := fileIdentities.CollectFile(mods[i].Path, []string{"process.module"})
			pc.attachModuleFileIdentity(&mods[i], identity)
		}
		detail.Modules = mods
		detail.ModulesTotal = len(mods)
		counts.Modules = len(mods)
		utils.Debug(comp, "PID %d (%s): 模块采集成功, %d 个模块", p.PID, p.ProcessName, len(mods))
	} else {
		utils.Debug(comp, "PID %d (%s): 模块采集失败: %v", p.PID, p.ProcessName, err)
	}

	wins, err := pc.collectProcessWindowsForPID(int32(p.PID))
	if err == nil {
		detail.Windows = wins
		counts.Windows = len(wins)
		if len(wins) > 0 {
			utils.Debug(comp, "PID %d (%s): 窗口采集成功, %d 个窗口", p.PID, p.ProcessName, len(wins))
		}
	} else {
		utils.Debug(comp, "PID %d (%s): 窗口采集失败: %v", p.PID, p.ProcessName, err)
	}

	handles, err := collectProcessHandles(int32(p.PID))
	if err == nil {
		detail.Handles = handles
		counts.Handles = len(handles)
		utils.Debug(comp, "PID %d (%s): 句柄采集成功, %d 个句柄", p.PID, p.ProcessName, len(handles))
	} else {
		utils.Debug(comp, "PID %d (%s): 句柄采集失败: %v", p.PID, p.ProcessName, err)
	}

	conns, err := proc.Connections()
	if err == nil {
		for i, conn := range conns {
			stateCode := 0
			switch conn.Status {
			case "ESTABLISHED":
				stateCode = 5
			case "LISTEN":
				stateCode = 2
			case "CLOSE_WAIT":
				stateCode = 8
			}

			connType := "TCP"
			if conn.Type == 2 {
				connType = "UDP"
			}

			family := "AF_INET"
			if conn.Family == 10 {
				family = "AF_INET6"
			}

			detail.NetworkConnections = append(detail.NetworkConnections, models.ProcessNetworkConnection{
				ID:            fmt.Sprintf("conn-%d-%d", p.PID, i),
				Protocol:      connType,
				Family:        family,
				LocalAddress:  conn.Laddr.IP,
				LocalPort:     int(conn.Laddr.Port),
				RemoteAddress: conn.Raddr.IP,
				RemotePort:    int(conn.Raddr.Port),
				StateCode:     stateCode,
				StateName:     conn.Status,
			})
		}
		counts.Connections = len(conns)
		if len(conns) > 0 {
			utils.Debug(comp, "PID %d (%s): 连接采集成功, %d 个连接", p.PID, p.ProcessName, len(conns))
		}
	} else {
		utils.Debug(comp, "PID %d (%s): 连接采集失败: %v", p.PID, p.ProcessName, err)
	}

	return detail, counts, nil
}

func (pc *ProcessCollector) collectProcessWindowsForPID(pid int32) ([]models.ProcessWindow, error) {
	if pc.windowSnapshot != nil {
		return pc.windowSnapshot[pid], nil
	}
	return collectProcessWindows(pid)
}

func (pc *ProcessCollector) getSessionID(p *process.Process) *int {
	return nil
}

func (pc *ProcessCollector) getBasePriority(p *process.Process) *int {
	nice, err := p.Nice()
	if err != nil {
		return nil
	}
	return utils.IntPtr(int(nice))
}

func (pc *ProcessCollector) getHandleCount(p *process.Process) *int {
	return getProcessHandleCount(p)
}

func (pc *ProcessCollector) getIs64Bit(exePath string) *bool {
	if runtime.GOARCH == "amd64" {
		t := true
		return &t
	}
	f := false
	return &f
}

func (pc *ProcessCollector) getProcessDomain(username string) (string, error) {
	if strings.Contains(username, "\\") {
		parts := strings.SplitN(username, "\\", 2)
		return parts[0], nil
	}
	return "", nil
}

func (pc *ProcessCollector) getBaseAddress(p *process.Process) *string {
	return getProcessBaseAddress(p)
}

func (pc *ProcessCollector) computeMD5(exePath string) string {
	file, err := os.Open(exePath)
	if err != nil {
		return ""
	}
	defer file.Close()

	sum := md5.New()
	if _, err := io.Copy(sum, file); err != nil {
		return ""
	}
	return hex.EncodeToString(sum.Sum(nil))
}

func (pc *ProcessCollector) fileIdentityCollector() *FileIdentityCollector {
	if pc.fileIdentities == nil {
		pc.fileIdentities = NewFileIdentityCollector()
	}
	return pc.fileIdentities
}

func (pc *ProcessCollector) attachProcessFileIdentity(info *models.ProcessBasicInfo, identity models.FileIdentity) {
	if info == nil {
		return
	}
	if identity.ID != "" {
		info.FileIdentityID = &identity.ID
	}
	if identity.SHA256 != "" {
		info.SHA256 = &identity.SHA256
	}
	if identity.HashState != "" {
		info.HashState = &identity.HashState
	}
	if identity.SignatureState != "" {
		info.SignatureState = &identity.SignatureState
	}
	if identity.SignerSubject != "" {
		info.SignerSubject = &identity.SignerSubject
	}
	if identity.PEOriginalFilename != "" {
		info.PEOriginalFilename = &identity.PEOriginalFilename
	}
}

func (pc *ProcessCollector) attachModuleFileIdentity(module *models.ProcessModule, identity models.FileIdentity) {
	if module == nil {
		return
	}
	if identity.ID != "" {
		module.FileIdentityID = &identity.ID
	}
	if identity.SHA256 != "" {
		module.SHA256 = &identity.SHA256
	}
	if identity.HashState != "" {
		module.HashState = &identity.HashState
	}
	if identity.SignatureState != "" {
		module.SignatureState = &identity.SignatureState
	}
	if identity.SignerSubject != "" {
		module.SignerSubject = &identity.SignerSubject
	}
	if identity.PEOriginalFilename != "" {
		module.PEOriginalFilename = &identity.PEOriginalFilename
	}
}

func classifySystemProcessMasquerade(processName, normalizedPath string, parentName *string, commandLine *string) []models.MasqueradeSignal {
	name := strings.ToLower(strings.TrimSpace(processName))
	if name != "svchost.exe" {
		return nil
	}

	base := strings.ToLower(filepath.Base(strings.TrimSpace(normalizedPath)))
	if base == "" {
		base = name
	}

	if filepath.Ext(base) != ".exe" {
		return []models.MasqueradeSignal{{
			Code:     "masquerade.extension_anomaly",
			Severity: "high",
			Message:  "系统进程扩展名异常",
		}}
	}

	if !isExpectedSystemSvchostPath(normalizedPath) {
		return []models.MasqueradeSignal{{
			Code:     "masquerade.path_anomaly",
			Severity: "high",
			Message:  "系统进程路径异常",
		}}
	}

	if parentName != nil {
		parent := strings.ToLower(strings.TrimSpace(*parentName))
		if parent != "" && parent != "services.exe" {
			return []models.MasqueradeSignal{{
				Code:     "masquerade.parent_anomaly",
				Severity: "high",
				Message:  "系统进程父进程异常",
			}}
		}
	}

	return nil
}

func isExpectedSystemSvchostPath(normalizedPath string) bool {
	switch strings.ToLower(strings.TrimSpace(normalizedPath)) {
	case `c:\windows\system32\svchost.exe`, `c:\windows\syswow64\svchost.exe`:
		return true
	default:
		return false
	}
}

func maxSignalSeverity(signals []models.MasqueradeSignal) string {
	rank := func(severity string) int {
		switch strings.ToLower(strings.TrimSpace(severity)) {
		case "critical":
			return 5
		case "high":
			return 4
		case "medium":
			return 3
		case "low":
			return 2
		case "info":
			return 1
		default:
			return 0
		}
	}

	maxRank := 0
	maxSeverity := ""
	for _, signal := range signals {
		if current := rank(signal.Severity); current > maxRank {
			maxRank = current
			maxSeverity = signal.Severity
		}
	}
	return maxSeverity
}

func formatHandleFallbackFields(objectTypeIndex uint16, attributes uint32) (string, string, string) {
	typeName := fmt.Sprintf("Type-%d", objectTypeIndex)
	return typeName, fmt.Sprintf("0x%x", attributes), typeName
}

func shouldResolveHandleName(typeName string) bool {
	switch strings.ToLower(strings.TrimSpace(typeName)) {
	case "file", "key", "event", "mutant", "semaphore", "section", "directory", "symboliclink", "desktop", "windowstation", "alpc port":
		return true
	default:
		return false
	}
}

func (pc *ProcessCollector) getMockProcessList() []*models.ProcessBasicInfo {
	pid := os.Getpid()
	ppid := os.Getppid()

	executable, _ := os.Executable()
	cmdLine := strings.Join(os.Args, " ")
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}

	currentProcess := &models.ProcessBasicInfo{
		ProcessName:  filepath.Base(executable),
		PID:          pid,
		CommandLine:  &cmdLine,
		ImagePath:    &executable,
		ParentPID:    &ppid,
		User:         &user,
		ThreadCount:  utils.IntPtr(1),
		BasePriority: utils.IntPtr(8),
	}

	return []*models.ProcessBasicInfo{currentProcess}
}
