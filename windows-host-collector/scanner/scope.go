package scanner

import (
	"collector-shared/orchestration"
	"windows-host-collector/forensics/filesystem"
	"windows-host-collector/models"
)

var quickStagePlan = orchestration.StagePlan{
	Stages: []orchestration.StageDefinition{
		{Key: "system", ScopeModules: []string{"host"}},
		{Key: "file_system", ScopeModules: []string{"file_system"}},
		{Key: "processes", ScopeModules: []string{"process"}},
		{Key: "network", ScopeModules: []string{"network"}},
		{Key: "services", ScopeModules: []string{"startup"}},
		{Key: "users", ScopeModules: []string{"users", "env_vars"}},
		{Key: "software", ScopeModules: []string{"software"}},
		{Key: "prefetch", ScopeModules: []string{"user_traces"}},
		{Key: "browser_history", ScopeModules: []string{"user_traces"}},
		{Key: "web_logs", ScopeModules: []string{"web_logs"}},
		{Key: "usb", ScopeModules: []string{"user_traces"}},
		{Key: "registries", ScopeModules: []string{"registry"}},
		{Key: "event_logs", ScopeModules: []string{"logs"}},
	},
	Dependencies: map[string][]string{
		"web_logs": {"processes", "network", "software"},
		"network":  {"browser_history"},
	},
}

func normalizeScanScopeModules(scope []string) map[string]struct{} {
	scopeSet := orchestration.NewScopeSet(scope)
	result := make(map[string]struct{}, len(scopeSet.List()))
	for _, module := range scopeSet.List() {
		result[module] = struct{}{}
	}
	return result
}

func stageEnabledByScope(scopeSet map[string]struct{}, stageKey string) bool {
	return quickStagePlan.StageEnabled(scopeSetFromMap(scopeSet), stageKey)
}

func shouldCollectFileSystem(scope []string) bool {
	if len(scope) == 0 {
		return true
	}
	_, enabled := normalizeScanScopeModules(scope)["file_system"]
	return enabled
}

func scopeSetFromMap(scopeSet map[string]struct{}) orchestration.ScopeSet {
	if len(scopeSet) == 0 {
		return orchestration.NewScopeSet(nil)
	}
	modules := make([]string, 0, len(scopeSet))
	for module := range scopeSet {
		modules = append(modules, module)
	}
	return orchestration.NewScopeSet(modules)
}

func applyScopeToQuickScanData(data *models.ScanEnvelope, scope []string) {
	if data == nil || len(scope) == 0 {
		return
	}
	scopeSet := normalizeScanScopeModules(scope)

	if _, enabled := scopeSet["host"]; !enabled {
		data.System = nil
		data.Resources = nil
		data.Hardware = nil
	}
	if _, enabled := scopeSet["process"]; !enabled {
		data.Processes = nil
		data.ProcessDetails = nil
		data.FileIdentities = nil
	}
	if _, enabled := scopeSet["network"]; !enabled {
		data.Network = models.NetworkData{}
	}
	if _, enabled := scopeSet["startup"]; !enabled {
		data.Services = models.ServicesData{}
	}
	if _, enabled := scopeSet["users"]; !enabled {
		data.Users = nil
	}
	if _, enabled := scopeSet["env_vars"]; !enabled {
		data.EnvVars = nil
	}
	if _, enabled := scopeSet["software"]; !enabled {
		data.Software = nil
	}
	if _, enabled := scopeSet["user_traces"]; !enabled {
		data.Prefetch = nil
		data.BrowserHistory = nil
		data.UsbRecords = nil
	}
	if _, enabled := scopeSet["web_logs"]; !enabled {
		data.WebLogSources = nil
		data.WebLogEntries = nil
	}
	if _, enabled := scopeSet["registry"]; !enabled {
		data.Registries = nil
	}
	if _, enabled := scopeSet["logs"]; !enabled {
		data.WindowsEventLogs = nil
	}
	if _, enabled := scopeSet["file_system"]; !enabled {
		data.ForensicVolumes = nil
		data.ForensicDirectoryNodes = nil
		data.ForensicFileEntries = nil
		data.ForensicTimelineEvents = nil
		data.ForensicDiagnostics = filesystem.CollectorDiagnostics{}
	}
}
