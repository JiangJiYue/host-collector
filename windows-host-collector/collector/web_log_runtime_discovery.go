package collector

import (
	"sort"
	"strconv"
	"strings"

	"collector-shared/weblogdiscovery"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

type webLogRuntimeCandidate struct {
	ServerType      string
	ProcessName     string
	ProcessPID      int
	ListenPorts     []int
	ExecutablePath  string
	CommandLine     string
	InstallLocation string
	ConfigHints     []string
	Evidence        []string
}

func buildRuntimeWebLogCandidates(ctx WebLogDiscoveryContext) []webLogRuntimeCandidate {
	candidates := make([]webLogRuntimeCandidate, 0, len(ctx.Processes))
	sharedCandidates := weblogdiscovery.BuildRuntimeCandidates(buildSharedWebLogDiscoveryContext(ctx))
	for _, candidate := range sharedCandidates {
		candidates = append(candidates, webLogRuntimeCandidate{
			ServerType:     candidate.ServerType,
			ProcessName:    candidate.ProcessName,
			ProcessPID:     candidate.ProcessPID,
			ListenPorts:    append([]int(nil), candidate.ListenPorts...),
			ExecutablePath: candidate.ExecutablePath,
			CommandLine:    candidate.CommandLine,
			ConfigHints:    append([]string(nil), candidate.ConfigHints...),
			Evidence:       append([]string(nil), candidate.Evidence...),
		})
	}

	for _, process := range ctx.Processes {
		if process == nil {
			continue
		}

		detailInfo := process
		if detail := ctx.ProcessDetails[process.PID]; detail != nil && detail.BasicInfo != nil {
			detailInfo = mergeProcessInfo(process, detail.BasicInfo)
		}

		baseCandidate := webLogRuntimeCandidate{
			ProcessName:    detailInfo.ProcessName,
			ProcessPID:     detailInfo.PID,
			CommandLine:    runtimeStringValue(detailInfo.CommandLine),
			ExecutablePath: runtimeStringValue(detailInfo.ImagePath),
		}

		name := strings.ToLower(baseCandidate.ProcessName)
		switch name {
		case "php-cgi.exe":
			processCandidates := buildPHPStudyRuntimeCandidates(baseCandidate, ctx.Software)
			if len(processCandidates) == 0 {
				continue
			}
			candidates = append(candidates, hydrateWindowsRuntimeCandidates(ctx, processCandidates)...)
		}
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		left := runtimeCandidateSortKey(candidates[i])
		right := runtimeCandidateSortKey(candidates[j])
		return left < right
	})

	deduped := dedupeRuntimeCandidates(candidates)
	for _, candidate := range deduped {
		utils.Info("Collector", "Web日志运行时发现候选进程: serverType=%s processName=%s processPid=%d installLocation=%s evidence=%v",
			candidate.ServerType, candidate.ProcessName, candidate.ProcessPID, runtimeHintToFSPath(candidate.InstallLocation), candidate.Evidence)
		for _, port := range candidate.ListenPorts {
			utils.Info("Collector", "Web日志运行时监听端口关联: serverType=%s processName=%s processPid=%d port=%d evidence=%v",
				candidate.ServerType, candidate.ProcessName, candidate.ProcessPID, port, candidate.Evidence)
		}
		for _, configHint := range candidate.ConfigHints {
			utils.Info("Collector", "Web日志运行时配置推导: serverType=%s processName=%s processPid=%d configPath=%s installLocation=%s evidence=%v",
				candidate.ServerType, candidate.ProcessName, candidate.ProcessPID, runtimeHintToFSPath(configHint), runtimeHintToFSPath(candidate.InstallLocation), candidate.Evidence)
		}
	}

	return deduped
}

func buildSharedWebLogDiscoveryContext(ctx WebLogDiscoveryContext) weblogdiscovery.Context {
	shared := weblogdiscovery.Context{
		Platform:  weblogdiscovery.PlatformWindows,
		Processes: make([]weblogdiscovery.ProcessSignal, 0, len(ctx.Processes)),
		Listeners: make([]weblogdiscovery.ListenerSignal, 0, len(ctx.NetworkSessions)),
	}
	for _, process := range ctx.Processes {
		if process == nil {
			continue
		}
		detailInfo := process
		if detail := ctx.ProcessDetails[process.PID]; detail != nil && detail.BasicInfo != nil {
			detailInfo = mergeProcessInfo(process, detail.BasicInfo)
		}
		shared.Processes = append(shared.Processes, weblogdiscovery.ProcessSignal{
			PID:            detailInfo.PID,
			Name:           detailInfo.ProcessName,
			CommandLine:    runtimeStringValue(detailInfo.CommandLine),
			ExecutablePath: runtimeStringValue(detailInfo.ImagePath),
		})
		if detail := ctx.ProcessDetails[detailInfo.PID]; detail != nil {
			for _, connection := range detail.NetworkConnections {
				if !strings.EqualFold(connection.StateName, "LISTEN") {
					continue
				}
				shared.Listeners = append(shared.Listeners, weblogdiscovery.ListenerSignal{
					ProcessPID:  detailInfo.PID,
					ProcessName: detailInfo.ProcessName,
					Port:        connection.LocalPort,
				})
			}
		}
	}
	for _, session := range ctx.NetworkSessions {
		if !strings.EqualFold(session.StateName, "LISTEN") {
			continue
		}
		shared.Listeners = append(shared.Listeners, weblogdiscovery.ListenerSignal{
			ProcessName: session.ProcessName,
			Port:        session.LocalPort,
		})
	}
	return shared
}

func hydrateWindowsRuntimeCandidates(ctx WebLogDiscoveryContext, processCandidates []webLogRuntimeCandidate) []webLogRuntimeCandidate {
	listenPortsByProcessName := map[string][]int{}
	for _, session := range ctx.NetworkSessions {
		if !strings.EqualFold(session.StateName, "LISTEN") {
			continue
		}
		key := strings.ToLower(session.ProcessName)
		listenPortsByProcessName[key] = append(listenPortsByProcessName[key], session.LocalPort)
	}

	hydrated := make([]webLogRuntimeCandidate, 0, len(processCandidates))
	for i := range processCandidates {
		candidate := &processCandidates[i]
		if detail := ctx.ProcessDetails[candidate.ProcessPID]; detail != nil {
			addListenPortsFromProcessConnections(candidate, detail.NetworkConnections)
		}
		if len(candidate.ListenPorts) == 0 {
			for _, port := range listenPortsByProcessName[strings.ToLower(candidate.ProcessName)] {
				addInt(&candidate.ListenPorts, port)
				addString(&candidate.Evidence, "LISTEN_PORT_MATCH")
			}
		}
		if len(candidate.ConfigHints) == 0 {
			continue
		}
		sort.Ints(candidate.ListenPorts)
		sort.Strings(candidate.ConfigHints)
		sort.Strings(candidate.Evidence)
		hydrated = append(hydrated, *candidate)
	}
	return hydrated
}

func buildPHPStudyRuntimeCandidates(base webLogRuntimeCandidate, software []models.InstalledSoftwareItem) []webLogRuntimeCandidate {
	addString(&base.Evidence, "PROCESS_NAME_MATCH")
	installLocation := matchPHPStudyInstallLocation(base.ExecutablePath, software)
	if installLocation == "" {
		return nil
	}
	base.InstallLocation = installLocation
	addString(&base.Evidence, "SOFTWARE_INSTALL_LOCATION_HINT")
	addString(&base.Evidence, "PHPSTUDY_LAYOUT_MATCH")

	configs := []struct {
		serverType string
		configHint string
	}{
		{
			serverType: "nginx",
			configHint: joinWindowsPath(installLocation, "Extensions", "Nginx*", "conf", "nginx.conf"),
		},
		{
			serverType: "apache",
			configHint: joinWindowsPath(installLocation, "Extensions", "Apache*", "conf", "httpd.conf"),
		},
		{
			serverType: "tomcat",
			configHint: joinWindowsPath(installLocation, "Extensions", "Tomcat*", "conf", "server.xml"),
		},
	}

	candidates := make([]webLogRuntimeCandidate, 0, len(configs))
	for _, config := range configs {
		candidate := base
		candidate.ServerType = config.serverType
		candidate.ConfigHints = nil
		addString(&candidate.ConfigHints, config.configHint)
		candidates = append(candidates, candidate)
	}
	return candidates
}

func addListenPortsFromProcessConnections(candidate *webLogRuntimeCandidate, connections []models.ProcessNetworkConnection) {
	for _, connection := range connections {
		if !strings.EqualFold(connection.StateName, "LISTEN") {
			continue
		}
		addInt(&candidate.ListenPorts, connection.LocalPort)
		addString(&candidate.Evidence, "LISTEN_PORT_MATCH")
	}
}

func mergeProcessInfo(base *models.ProcessBasicInfo, detail *models.ProcessBasicInfo) *models.ProcessBasicInfo {
	merged := *base
	if merged.ProcessName == "" {
		merged.ProcessName = detail.ProcessName
	}
	if merged.PID == 0 {
		merged.PID = detail.PID
	}
	if merged.CommandLine == nil {
		merged.CommandLine = detail.CommandLine
	}
	if merged.ImagePath == nil {
		merged.ImagePath = detail.ImagePath
	}
	return &merged
}

func matchPHPStudyInstallLocation(executablePath string, software []models.InstalledSoftwareItem) string {
	executablePathLower := strings.ToLower(executablePath)
	for _, item := range software {
		if !strings.Contains(strings.ToLower(item.Name), "phpstudy") {
			continue
		}
		if item.InstallLocation == "" {
			continue
		}
		if executablePath == "" || strings.HasPrefix(executablePathLower, strings.ToLower(item.InstallLocation)+"\\") || strings.EqualFold(executablePath, item.InstallLocation) {
			return item.InstallLocation
		}
	}
	if executablePath == "" {
		return ""
	}
	parts := splitWindowsPath(executablePath)
	for i, part := range parts {
		if strings.HasPrefix(strings.ToLower(part), "phpstudy") {
			return strings.Join(parts[:i+1], `\`)
		}
	}
	return ""
}

func dedupeRuntimeCandidates(candidates []webLogRuntimeCandidate) []webLogRuntimeCandidate {
	if len(candidates) == 0 {
		return nil
	}
	deduped := make([]webLogRuntimeCandidate, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		key := runtimeCandidateSortKey(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		deduped = append(deduped, candidate)
	}
	return deduped
}

func runtimeCandidateSortKey(candidate webLogRuntimeCandidate) string {
	return strings.Join([]string{
		candidate.ServerType,
		strings.ToLower(candidate.ProcessName),
		stringInt(candidate.ProcessPID),
		strings.ToLower(candidate.ExecutablePath),
		strings.Join(candidate.ConfigHints, "|"),
	}, "\x00")
}

func addString(target *[]string, value string) {
	if value == "" {
		return
	}
	for _, existing := range *target {
		if existing == value {
			return
		}
	}
	*target = append(*target, value)
}

func addInt(target *[]int, value int) {
	for _, existing := range *target {
		if existing == value {
			return
		}
	}
	*target = append(*target, value)
}

func runtimeStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func splitWindowsPath(path string) []string {
	return strings.FieldsFunc(path, func(r rune) bool {
		return r == '\\' || r == '/'
	})
}

func joinWindowsPath(parts ...string) string {
	filtered := make([]string, 0, len(parts))
	for i, part := range parts {
		if part == "" {
			continue
		}
		part = strings.ReplaceAll(part, "/", `\`)
		if i > 0 {
			part = strings.Trim(part, `\`)
		} else {
			part = strings.TrimRight(part, `\`)
		}
		if part != "" {
			filtered = append(filtered, part)
		}
	}
	return strings.Join(filtered, `\`)
}

func stringInt(v int) string {
	return strconv.Itoa(v)
}
