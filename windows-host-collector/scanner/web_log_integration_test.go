package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"collector-shared/authpolicy"
	"windows-host-collector/collector"
	"windows-host-collector/models"
)

func TestQuickScannerPassesAttachedPolicyWindowToLogCollectors(t *testing.T) {
	fixedNow := mustParseScannerTime(t, "2026-04-29T12:00:00Z")
	restoreNow := setQuickScanNowForTesting(fixedNow)
	defer restoreNow()

	var logWindowStarts []time.Time
	restoreLogObserver := collector.SetLogCollectorWindowObserverForTesting(func(start time.Time) {
		logWindowStarts = append(logWindowStarts, start)
	})
	defer restoreLogObserver()
	restoreLogHook := setQuickScanLogCollectHookForTesting(func(ctx context.Context, _ *collector.LogCollector) (*collector.LogCollectionResult, error) {
		return &collector.LogCollectionResult{WindowsEventLogs: []models.WindowsLogItem{}}, nil
	})
	defer restoreLogHook()

	var webLogWindowStarts []time.Time
	restoreWebLogObserver := collector.SetWebLogCollectorWindowObserverForTesting(func(start time.Time) {
		webLogWindowStarts = append(webLogWindowStarts, start)
	})
	defer restoreWebLogObserver()

	scanner := NewQuickScanner().
		WithScope([]string{"logs", "web_logs"}).
		WithPolicy(&authpolicy.Policy{LogWindowDays: 14})
	_, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatalf("quick scan: %v", err)
	}

	want := mustParseScannerTime(t, "2026-04-15T12:00:00Z")
	if len(logWindowStarts) != 1 {
		t.Fatalf("expected one log collector window start, got %#v", logWindowStarts)
	}
	if len(webLogWindowStarts) != 1 {
		t.Fatalf("expected one web log collector window start, got %#v", webLogWindowStarts)
	}
	if !logWindowStarts[0].Equal(want) {
		t.Fatalf("expected log collector window %s, got %s", want, logWindowStarts[0])
	}
	if !webLogWindowStarts[0].Equal(want) {
		t.Fatalf("expected web log collector window %s, got %s", want, webLogWindowStarts[0])
	}
}

func TestQuickScannerReportsEventLogRunningStatusOnlyOnce(t *testing.T) {
	restoreLogHook := setQuickScanLogCollectHookForTesting(func(ctx context.Context, logCollector *collector.LogCollector) (*collector.LogCollectionResult, error) {
		logCollector.ReportForTesting(collector.LogProgress{Channel: "System", ChannelsDone: 0, ChannelsTotal: 2, EventsRead: 1, TotalEvents: 1})
		logCollector.ReportForTesting(collector.LogProgress{Channel: "Application", ChannelsDone: 1, ChannelsTotal: 2, EventsRead: 2, TotalEvents: 3})
		return &collector.LogCollectionResult{WindowsEventLogs: []models.WindowsLogItem{}}, nil
	})
	defer restoreLogHook()

	var progressEvents []ScanProgress
	_, err := NewQuickScanner().
		WithScope([]string{"logs"}).
		WithProgress(func(progress ScanProgress) {
			if progress.StageKey == "event_logs" {
				progressEvents = append(progressEvents, progress)
			}
		}).
		Scan(context.Background())
	if err != nil {
		t.Fatalf("quick scan: %v", err)
	}

	var runningCount int
	for _, event := range progressEvents {
		if event.StageState == stageStateRunning && event.Detail == "事件日志采集中" {
			runningCount++
		}
	}
	if runningCount != 1 {
		t.Fatalf("expected one generic event log running status, got %d from %#v", runningCount, progressEvents)
	}
	if got := progressEvents[len(progressEvents)-1]; got.StageState != string(models.StageCompleted) || got.Detail != "事件日志采集完成" {
		t.Fatalf("expected event log completion last, got %#v", got)
	}
}

func TestHostScannerPassesValidatedPolicyWindowToLogCollectors(t *testing.T) {
	fixedNow := mustParseScannerTime(t, "2026-04-29T12:00:00Z")
	restoreNow := setQuickScanNowForTesting(fixedNow)
	defer restoreNow()

	var logWindowStarts []time.Time
	restoreLogObserver := collector.SetLogCollectorWindowObserverForTesting(func(start time.Time) {
		logWindowStarts = append(logWindowStarts, start)
	})
	defer restoreLogObserver()
	restoreLogHook := setQuickScanLogCollectHookForTesting(func(ctx context.Context, _ *collector.LogCollector) (*collector.LogCollectionResult, error) {
		return &collector.LogCollectionResult{WindowsEventLogs: []models.WindowsLogItem{}}, nil
	})
	defer restoreLogHook()

	var webLogWindowStarts []time.Time
	restoreWebLogObserver := collector.SetWebLogCollectorWindowObserverForTesting(func(start time.Time) {
		webLogWindowStarts = append(webLogWindowStarts, start)
	})
	defer restoreWebLogObserver()

	_, err := NewHostScanner().
		WithScope([]string{"logs", "web_logs"}).
		WithPolicy(&authpolicy.Policy{LogWindowDays: 30}).
		Scan(context.Background())
	if err != nil {
		t.Fatalf("host scan: %v", err)
	}

	want := mustParseScannerTime(t, "2026-03-30T12:00:00Z")
	if len(logWindowStarts) != 1 {
		t.Fatalf("expected one log collector window start, got %#v", logWindowStarts)
	}
	if len(webLogWindowStarts) != 1 {
		t.Fatalf("expected one web log collector window start, got %#v", webLogWindowStarts)
	}
	if !logWindowStarts[0].Equal(want) {
		t.Fatalf("expected log collector window %s, got %s", want, logWindowStarts[0])
	}
	if !webLogWindowStarts[0].Equal(want) {
		t.Fatalf("expected web log collector window %s, got %s", want, webLogWindowStarts[0])
	}
}

func TestQuickScannerIncludesWebLogStageAndResults(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "nginx", "logs")
	confDir := filepath.Join(root, "nginx", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	logPath := filepath.Join(logDir, "access.log")
	logBody := "1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(logPath) + ";\n}\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	collector.SetWebLogDiscoveryOverridesForTesting(collector.WebLogDiscoveryOverrideConfig{
		NginxConfigs: []string{confPath},
		ScanOptions: collector.WebLogScanOverrideConfig{
			MaxDepth:          2,
			MaxFilesPerRoot:   10,
			MaxTotalFiles:     10,
			MaxSampleBytes:    4096,
			AllowedExtensions: []string{".log", ".txt"},
		},
	})
	defer collector.SetWebLogDiscoveryOverridesForTesting(collector.WebLogDiscoveryOverrideConfig{})

	hs := NewHostScanner()
	data, err := hs.Scan(context.Background())
	if err != nil {
		t.Fatalf("host scan: %v", err)
	}

	if len(data.WebLogSources) != 1 {
		t.Fatalf("expected 1 webLogSources entry, got %#v", data.WebLogSources)
	}
	if len(data.WebLogEntries) != 1 {
		t.Fatalf("expected 1 webLogEntries entry, got %#v", data.WebLogEntries)
	}

	stageRows := hs.stageRowsSnapshot()
	if _, ok := stageRows["web_logs"]; !ok {
		t.Fatalf("expected web_logs stage row to be reported, got %#v", stageRows)
	}
}

func TestQuickScannerPassesRuntimeContextToWebLogCollector(t *testing.T) {
	imagePath := `D:\Env\nginx\nginx.exe`
	data := &models.ScanEnvelope{
		Processes: []*models.ProcessBasicInfo{
			{PID: 101, ProcessName: "nginx.exe"},
		},
		ProcessDetails: map[int]*models.ProcessDetail{
			101: {
				BasicInfo: &models.ProcessBasicInfo{
					PID:         101,
					ProcessName: "nginx.exe",
					ImagePath:   &imagePath,
				},
			},
		},
		Network: models.NetworkData{
			Sessions: []models.NetworkSession{
				{ProcessName: "nginx.exe", LocalPort: 80, StateName: "LISTEN"},
			},
		},
		Software: []models.InstalledSoftwareItem{
			{Name: "phpstudy", InstallLocation: `D:\Env\phpstudy_pro`},
		},
	}

	collector := collector.NewWebLogCollector().
		WithDiscoveryContext(collector.WebLogDiscoveryContext{
			Processes:       data.Processes,
			ProcessDetails:  data.ProcessDetails,
			NetworkSessions: data.Network.Sessions,
			Software:        data.Software,
		})

	if collector == nil {
		t.Fatal("expected collector with runtime discovery context")
	}
}

func TestQuickScannerWebLogStageUsesDiscoveryContext(t *testing.T) {
	root := t.TempDir()
	logDir := filepath.Join(root, "nginx", "logs")
	confDir := filepath.Join(root, "nginx", "conf")
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}

	logPath := filepath.Join(logDir, "access.log")
	logBody := "1.2.3.4 - - [21/Apr/2026:12:01:02 +0800] \"GET / HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
	if err := os.WriteFile(logPath, []byte(logBody), 0o644); err != nil {
		t.Fatalf("write access log: %v", err)
	}

	confPath := filepath.Join(confDir, "nginx.conf")
	confBody := "events {}\nhttp {\n  access_log " + filepath.ToSlash(logPath) + ";\n}\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("write nginx conf: %v", err)
	}

	collector.SetWebLogDiscoveryOverridesForTesting(collector.WebLogDiscoveryOverrideConfig{
		NginxConfigs: []string{confPath},
		ScanOptions: collector.WebLogScanOverrideConfig{
			MaxDepth:          2,
			MaxFilesPerRoot:   10,
			MaxTotalFiles:     10,
			MaxSampleBytes:    4096,
			AllowedExtensions: []string{".log", ".txt"},
		},
	})
	defer collector.SetWebLogDiscoveryOverridesForTesting(collector.WebLogDiscoveryOverrideConfig{})

	processesRelease := make(chan struct{})
	networkRelease := make(chan struct{})
	softwareRelease := make(chan struct{})
	defer closeIfOpen(processesRelease)
	defer closeIfOpen(networkRelease)
	defer closeIfOpen(softwareRelease)

	imagePath := `D:\Env\nginx\nginx.exe`
	wantProcesses := []*models.ProcessBasicInfo{
		{PID: 101, ProcessName: "nginx.exe"},
	}
	wantProcessDetails := map[int]*models.ProcessDetail{
		101: {
			BasicInfo: &models.ProcessBasicInfo{
				PID:         101,
				ProcessName: "nginx.exe",
				ImagePath:   &imagePath,
			},
		},
	}
	wantNetworkSessions := []models.NetworkSession{
		{ProcessName: "nginx.exe", LocalPort: 80, StateName: "LISTEN"},
	}
	wantSoftware := []models.InstalledSoftwareItem{
		{Name: "phpstudy", InstallLocation: `D:\Env\phpstudy_pro`},
	}
	wantFileIdentities := []models.FileIdentity{
		{ID: "file-id-1", Path: imagePath, SHA256: "sha256-value", HashState: "completed"},
	}

	processesEntered := make(chan struct{})
	networkEntered := make(chan struct{})
	softwareEntered := make(chan struct{})
	observerCalled := make(chan collector.WebLogDiscoveryContext, 1)

	restoreProcessHook := setQuickScanProcessCollectHookForTesting(func(ctx context.Context, _ *collector.ProcessCollector) (*collector.ProcessCollectionResult, error) {
		close(processesEntered)
		<-processesRelease
		return &collector.ProcessCollectionResult{
			Processes:      wantProcesses,
			ProcessDetails: wantProcessDetails,
			FileIdentities: wantFileIdentities,
		}, nil
	})
	defer restoreProcessHook()

	restoreNetworkHook := setQuickScanNetworkCollectHookForTesting(func(ctx context.Context, _ *collector.NetworkCollector) (*collector.NetworkCollectionResult, error) {
		close(networkEntered)
		<-networkRelease
		return &collector.NetworkCollectionResult{
			Sessions: wantNetworkSessions,
		}, nil
	})
	defer restoreNetworkHook()

	restoreSoftwareHook := setQuickScanSoftwareCollectHookForTesting(func(ctx context.Context, _ *collector.SoftwareCollector) (*collector.SoftwareCollectionResult, error) {
		close(softwareEntered)
		<-softwareRelease
		return &collector.SoftwareCollectionResult{
			Software: wantSoftware,
		}, nil
	})
	defer restoreSoftwareHook()

	restoreObserver := collector.SetWebLogDiscoveryContextObserverForTesting(func(ctx collector.WebLogDiscoveryContext) {
		observerCalled <- ctx
	})
	defer restoreObserver()

	hs := NewHostScanner()
	scanDone := make(chan struct{})
	var (
		data *models.ScanEnvelope
		err  error
	)
	go func() {
		defer close(scanDone)
		data, err = hs.Scan(context.Background())
	}()

	waitForSignal(t, "process hook entered", processesEntered)
	waitForSignal(t, "network hook entered", networkEntered)
	waitForSignal(t, "software hook entered", softwareEntered)

	assertNoSignal(t, "web log observer before dependency release", observerCalled)

	close(processesRelease)
	close(networkRelease)
	close(softwareRelease)

	select {
	case <-scanDone:
	case <-time.After(5 * time.Second):
		t.Fatal("host scan did not complete")
	}

	if err != nil {
		t.Fatalf("host scan: %v", err)
	}

	if len(data.WebLogSources) != 1 {
		t.Fatalf("expected 1 webLogSources entry, got %#v", data.WebLogSources)
	}
	if len(data.FileIdentities) != 1 || data.FileIdentities[0].ID != "file-id-1" {
		t.Fatalf("expected file identities from process collection to be preserved, got %#v", data.FileIdentities)
	}

	observedCtx := waitForObserverContext(t, observerCalled)
	if len(observedCtx.Processes) != len(wantProcesses) {
		t.Fatalf("expected %d processes in discovery context, got %#v", len(wantProcesses), observedCtx.Processes)
	}
	if len(observedCtx.ProcessDetails) != len(wantProcessDetails) {
		t.Fatalf("expected %d process details in discovery context, got %#v", len(wantProcessDetails), observedCtx.ProcessDetails)
	}
	if len(observedCtx.NetworkSessions) != len(wantNetworkSessions) {
		t.Fatalf("expected %d network sessions in discovery context, got %#v", len(wantNetworkSessions), observedCtx.NetworkSessions)
	}
	if len(observedCtx.Software) != len(wantSoftware) {
		t.Fatalf("expected %d software entries in discovery context, got %#v", len(wantSoftware), observedCtx.Software)
	}
}

func waitForSignal(t *testing.T, description string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func mustParseScannerTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

func assertNoSignal(t *testing.T, description string, ch <-chan collector.WebLogDiscoveryContext) {
	t.Helper()
	select {
	case ctx := <-ch:
		t.Fatalf("unexpected signal for %s: %#v", description, ctx)
	default:
	}
}

func waitForObserverContext(t *testing.T, ch <-chan collector.WebLogDiscoveryContext) collector.WebLogDiscoveryContext {
	t.Helper()
	select {
	case ctx := <-ch:
		return ctx
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for web log discovery observer")
		return collector.WebLogDiscoveryContext{}
	}
}

func closeIfOpen(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}
