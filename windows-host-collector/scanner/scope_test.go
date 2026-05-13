package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"windows-host-collector/collector"
	"windows-host-collector/forensics/filesystem"
	"windows-host-collector/models"
)

type scannerDNSResolverFunc func(context.Context, string) ([]string, error)

func (fn scannerDNSResolverFunc) LookupHost(ctx context.Context, host string) ([]string, error) {
	return fn(ctx, host)
}

func TestHostScannerScopeIncludesFileSystemStage(t *testing.T) {
	hostOnly := NewHostScanner().WithScope([]string{"host"})
	if hostOnly.shouldRunStage("file_system") {
		t.Fatalf("did not expect file_system stage without file_system scope")
	}

	fileSystemOnly := NewHostScanner().WithScope([]string{"file_system"})
	if !fileSystemOnly.shouldRunStage("file_system") {
		t.Fatalf("expected file_system stage with file_system scope")
	}
	if fileSystemOnly.shouldRunStage("registries") {
		t.Fatalf("did not expect registries stage without registry scope")
	}

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	scannerDir := filepath.Dir(currentFile)
	for _, legacySymbol := range []string{"NewFullScanner", "NewCustomScanner"} {
		if scannerPackageContainsSymbol(t, scannerDir, legacySymbol) {
			t.Fatalf("expected scanner package to stop referencing %s", legacySymbol)
		}
	}
}

func TestHostScannerCollectsFileSystemStageWhenRequested(t *testing.T) {
	restore := setQuickScanForensicFileSystemCollectHookForTesting(func(ctx context.Context, c *collector.ForensicFileSystemCollector) (*collector.ForensicFileSystemResult, error) {
		if c == nil {
			t.Fatalf("expected forensic file system collector")
		}
		return &collector.ForensicFileSystemResult{
			Volumes: []filesystem.VolumeInfo{
				{VolumeID: "volume-1", DevicePath: `\\.\C:`, FileSystem: "NTFS"},
			},
			DirectoryNodes: []filesystem.DirectoryNode{
				{NodeID: "dir-1", VolumeID: "volume-1", MFTEntry: 5, ParentMFTEntry: 5, Path: `C:\`, Name: "C:"},
			},
			FileEntries: []filesystem.FileEntry{
				{EntryID: "file-1", VolumeID: "volume-1", MFTEntry: 42, ParentMFTEntry: 5, Path: `C:\Windows\notepad.exe`, Name: "notepad.exe", HashState: "skipped"},
			},
			TimelineEvents: []filesystem.TimelineEvent{
				{EventID: "event-1", VolumeID: "volume-1", EntryID: "file-1", Path: `C:\Windows\notepad.exe`, EventType: "modified", Timestamp: "2026-04-22T00:00:00Z"},
			},
			Diagnostics: filesystem.CollectorDiagnostics{
				TotalParsedRecords:        2,
				TotalFileEntriesEmitted:   1,
				TimestampCoverageModified: 1,
			},
		}, nil
	})
	defer restore()

	hs := NewHostScanner().WithScope([]string{"file_system"})

	data, err := hs.Scan(context.Background())
	if err != nil {
		t.Fatalf("host scan: %v", err)
	}

	stage, ok := hs.stageRowsSnapshot()["file_system"]
	if !ok {
		t.Fatalf("expected file_system stage row, got %#v", hs.stageRowsSnapshot())
	}
	if stage.State != string(models.StageCompleted) {
		t.Fatalf("expected file_system stage state %q, got %#v", models.StageCompleted, stage)
	}
	if stage.Detail != "文件系统取证采集完成" {
		t.Fatalf("expected file_system completion detail, got %#v", stage)
	}
	if len(data.ForensicVolumes) != 1 || data.ForensicVolumes[0].VolumeID != "volume-1" {
		t.Fatalf("expected forensic volumes in scan envelope, got %#v", data.ForensicVolumes)
	}
	if len(data.ForensicDirectoryNodes) != 1 || data.ForensicDirectoryNodes[0].NodeID != "dir-1" {
		t.Fatalf("expected forensic directory nodes in scan envelope, got %#v", data.ForensicDirectoryNodes)
	}
	if len(data.ForensicFileEntries) != 1 || data.ForensicFileEntries[0].EntryID != "file-1" {
		t.Fatalf("expected forensic file entries in scan envelope, got %#v", data.ForensicFileEntries)
	}
	if len(data.ForensicTimelineEvents) != 1 || data.ForensicTimelineEvents[0].EventID != "event-1" {
		t.Fatalf("expected forensic timeline events in scan envelope, got %#v", data.ForensicTimelineEvents)
	}
	if data.ForensicDiagnostics.TotalParsedRecords != 2 {
		t.Fatalf("expected forensic diagnostics in scan envelope, got %#v", data.ForensicDiagnostics)
	}
}

func TestQuickScannerScopeKeepsWebLogsButTrimsDependencyOutputs(t *testing.T) {
	qs := NewQuickScanner().WithScope([]string{"web_logs"})

	if !qs.shouldRunStage("web_logs") {
		t.Fatalf("expected web_logs stage to run")
	}
	for _, stageKey := range []string{"processes", "network", "software"} {
		if !qs.shouldRunStage(stageKey) {
			t.Fatalf("expected dependency stage %s to run for web_logs scope", stageKey)
		}
	}
	if qs.shouldRunStage("services") {
		t.Fatalf("did not expect unrelated services stage to run")
	}

	data := &models.ScanEnvelope{
		Processes: []*models.ProcessBasicInfo{
			{PID: 100, ProcessName: "nginx.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			100: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         100,
					ProcessName: "nginx.exe",
				},
			},
		},
		Network: models.NetworkData{
			Sessions: []models.NetworkSession{
				{ProcessName: "nginx.exe", LocalPort: 80},
			},
			DnsCache: []models.DnsCacheRecord{
				{Host: "example.com"},
			},
		},
		Software: []models.InstalledSoftwareItem{
			{Name: "phpstudy"},
		},
		WebLogSources: []models.WebLogSource{
			{ID: "source-1", Path: `D:\logs\access.log`},
		},
		WebLogEntries: []models.WebLogEntry{
			{SourceID: "source-1", URI: "/index.php"},
		},
	}

	applyScopeToQuickScanData(data, []string{"web_logs"})

	if len(data.WebLogSources) != 1 || len(data.WebLogEntries) != 1 {
		t.Fatalf("expected web log results to remain, got %#v %#v", data.WebLogSources, data.WebLogEntries)
	}
	if len(data.Processes) != 0 || len(data.ProcessDetails) != 0 {
		t.Fatalf("expected process dependency outputs to be trimmed, got %#v %#v", data.Processes, data.ProcessDetails)
	}
	if len(data.Network.Sessions) != 0 || len(data.Network.DnsCache) != 0 || len(data.Network.Hosts) != 0 || len(data.Network.Shares) != 0 {
		t.Fatalf("expected network dependency outputs to be trimmed, got %#v", data.Network)
	}
	if len(data.Software) != 0 {
		t.Fatalf("expected software dependency outputs to be trimmed, got %#v", data.Software)
	}
}

func TestQuickScannerEnrichesDNSCacheFromBrowserHistoryBeforeReturning(t *testing.T) {
	restoreNetworkHook := setQuickScanNetworkCollectHookForTesting(func(ctx context.Context, c *collector.NetworkCollector) (*collector.NetworkCollectionResult, error) {
		return &collector.NetworkCollectionResult{
			DNS: []models.DnsCacheRecord{
				{ID: "dns-0", Host: "cached.example.com", RecordType: "A"},
			},
		}, nil
	})
	defer restoreNetworkHook()

	restoreBrowserHistoryHook := setQuickScanBrowserHistoryCollectHookForTesting(func(ctx context.Context, c *collector.BrowserHistoryCollector) (*collector.BrowserHistoryCollectionResult, error) {
		return &collector.BrowserHistoryCollectionResult{
			Entries: []models.BrowserHistoryEntry{
				{URL: "https://history.example.com/path"},
				{URL: "https://cached.example.com/reused"},
			},
			Total: 2,
		}, nil
	})
	defer restoreBrowserHistoryHook()

	restoreResolver := collector.SetDNSResolverForTesting(scannerDNSResolverFunc(func(ctx context.Context, host string) ([]string, error) {
		switch host {
		case "cached.example.com":
			return []string{"203.0.113.20"}, nil
		case "history.example.com":
			return []string{"198.51.100.9"}, nil
		default:
			t.Fatalf("unexpected DNS lookup for %q", host)
			return nil, nil
		}
	}))
	defer restoreResolver()

	data, err := NewQuickScanner().
		WithScope([]string{"network"}).
		Scan(context.Background())
	if err != nil {
		t.Fatalf("quick scan: %v", err)
	}

	got := map[string]string{}
	for _, record := range data.Network.DnsCache {
		got[record.Host] = record.IPAddress
	}
	if got["cached.example.com"] != "203.0.113.20" {
		t.Fatalf("expected cached DNS record to be resolved, got %#v", data.Network.DnsCache)
	}
	if got["history.example.com"] != "198.51.100.9" {
		t.Fatalf("expected browser history domain to be resolved into DNS cache, got %#v", data.Network.DnsCache)
	}
	if len(data.BrowserHistory) != 0 {
		t.Fatalf("expected browser history dependency output to be trimmed for network-only scope, got %#v", data.BrowserHistory)
	}
}

func TestQuickScannerScopeCanSplitUsersAndEnvVars(t *testing.T) {
	usersOnly := &models.ScanEnvelope{
		Users: []models.LocalUserAccount{
			{Username: "48967"},
		},
		EnvVars: []models.EnvironmentVariable{
			{Key: "TEMP", Value: `C:\Temp`},
		},
	}
	applyScopeToQuickScanData(usersOnly, []string{"users"})
	if len(usersOnly.Users) != 1 {
		t.Fatalf("expected users to remain, got %#v", usersOnly.Users)
	}
	if len(usersOnly.EnvVars) != 0 {
		t.Fatalf("expected env vars to be trimmed, got %#v", usersOnly.EnvVars)
	}

	envOnly := &models.ScanEnvelope{
		Users: []models.LocalUserAccount{
			{Username: "48967"},
		},
		EnvVars: []models.EnvironmentVariable{
			{Key: "TEMP", Value: `C:\Temp`},
		},
	}
	applyScopeToQuickScanData(envOnly, []string{"env_vars"})
	if len(envOnly.Users) != 0 {
		t.Fatalf("expected users to be trimmed, got %#v", envOnly.Users)
	}
	if len(envOnly.EnvVars) != 1 {
		t.Fatalf("expected env vars to remain, got %#v", envOnly.EnvVars)
	}
}

func TestShouldCollectFileSystemDependsOnScope(t *testing.T) {
	if shouldCollectFileSystem([]string{"host", "network"}) {
		t.Fatalf("did not expect file system collection without file_system module")
	}
	if !shouldCollectFileSystem([]string{"host", "file_system"}) {
		t.Fatalf("expected file system collection with file_system module")
	}
}

func TestQuickStageScopeModulesMatchSupportedStages(t *testing.T) {
	expectedStageModules := map[string][]string{
		"system":          {"host"},
		"file_system":     {"file_system"},
		"processes":       {"process"},
		"network":         {"network"},
		"services":        {"startup"},
		"users":           {"users", "env_vars"},
		"software":        {"software"},
		"prefetch":        {"user_traces"},
		"browser_history": {"user_traces"},
		"web_logs":        {"web_logs"},
		"usb":             {"user_traces"},
		"registries":      {"registry"},
		"event_logs":      {"logs"},
	}

	if len(quickStagePlan.Stages) != len(expectedStageModules) {
		t.Fatalf("expected %d supported quick stages, got %#v", len(expectedStageModules), quickStagePlan.Stages)
	}

	actualStageModules := map[string][]string{}
	for _, stage := range quickStagePlan.Stages {
		actualStageModules[stage.Key] = stage.ScopeModules
	}
	for stageKey, expectedModules := range expectedStageModules {
		actualModules, ok := actualStageModules[stageKey]
		if !ok {
			t.Fatalf("expected quick stage scope entry for %s", stageKey)
		}
		if strings.Join(actualModules, ",") != strings.Join(expectedModules, ",") {
			t.Fatalf("expected %s modules %v, got %v", stageKey, expectedModules, actualModules)
		}
		scopeSet := make(map[string]struct{}, len(expectedModules))
		for _, module := range expectedModules {
			scopeSet[module] = struct{}{}
		}
		if !stageEnabledByScope(scopeSet, stageKey) {
			t.Fatalf("expected %s stage to resolve from supported modules %v", stageKey, expectedModules)
		}
	}

	if stageEnabledByScope(map[string]struct{}{"host": {}}, "event_logs") {
		t.Fatalf("did not expect event_logs stage without logs scope")
	}
}

func TestApplyScopeToQuickScanDataTrimsFileSystemWhenModuleDisabled(t *testing.T) {
	data := &models.ScanEnvelope{
		ForensicVolumes: []filesystem.VolumeInfo{
			{VolumeID: "volume-1"},
		},
		ForensicDirectoryNodes: []filesystem.DirectoryNode{
			{NodeID: "dir-1"},
		},
		ForensicFileEntries: []filesystem.FileEntry{
			{EntryID: "file-1"},
		},
		ForensicTimelineEvents: []filesystem.TimelineEvent{
			{EventID: "event-1"},
		},
	}

	applyScopeToQuickScanData(data, []string{"host"})

	if data.ForensicVolumes != nil || data.ForensicDirectoryNodes != nil || data.ForensicFileEntries != nil || data.ForensicTimelineEvents != nil {
		t.Fatalf("expected forensic file-system data to be trimmed when file_system module disabled, got %#v", data)
	}
	if data.ForensicDiagnostics.TotalParsedRecords != 0 ||
		data.ForensicDiagnostics.TotalEntriesEmitted != 0 ||
		len(data.ForensicDiagnostics.SkippedVolumes) != 0 {
		t.Fatalf("expected forensic diagnostics to be trimmed when file_system module disabled, got %#v", data.ForensicDiagnostics)
	}
}

func scannerPackageContainsSymbol(t *testing.T, dir, symbol string) bool {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read scanner dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if strings.Contains(string(body), symbol) {
			return true
		}
	}
	return false
}
