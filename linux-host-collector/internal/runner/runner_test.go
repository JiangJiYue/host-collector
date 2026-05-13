package runner

import (
	"path/filepath"
	"testing"
	"time"

	"collector-shared/appcore"
	"collector-shared/contracts"
	"linux-host-collector/internal/collectors/history"
	"linux-host-collector/internal/collectors/logs"
	"linux-host-collector/internal/collectors/weblogs"
)

func TestRunLocalScanBuildsSectionsAndUploadItemPlan(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:    filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:  "amd64",
		AgentID: "agent-linux-1",
		ScanID:  "scan-1",
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	if result.Envelope.Platform != "linux" {
		t.Fatalf("expected linux platform, got %#v", result.Envelope)
	}
	if result.Envelope.Sections["users"] == nil {
		t.Fatalf("expected users section")
	}
	if len(result.UploadItems) == 0 {
		t.Fatalf("expected upload item plan")
	}
	if result.UploadItems[0].ItemID != "host" {
		t.Fatalf("expected host upload item first, got %#v", result.UploadItems[0])
	}
}

func TestRunLocalScanEmitsSectionProgress(t *testing.T) {
	recorder := appcore.NewRecorder()

	_, err := RunLocalScan(Config{
		Root:       filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:     "amd64",
		AgentID:    "agent-linux-1",
		ScanID:     "scan-1",
		ScanScope:  []string{"host", "network"},
		StatusSink: recorder,
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}

	events := recorder.Events()
	if len(events) < 4 {
		t.Fatalf("expected progress events, got %#v", events)
	}
	assertHasProgress(t, events, "host", appcore.StateRunning)
	assertHasProgress(t, events, "host", appcore.StateCompleted)
	assertHasProgress(t, events, "network", appcore.StateRunning)
	assertHasProgress(t, events, "network", appcore.StateCompleted)
}

func TestRunLocalScanEmitsSkippedProgressForDisabledStages(t *testing.T) {
	recorder := appcore.NewRecorder()

	_, err := RunLocalScan(Config{
		Root:       filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:     "amd64",
		AgentID:    "agent-linux-1",
		ScanID:     "scan-1",
		ScanScope:  []string{"host"},
		StatusSink: recorder,
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}

	events := recorder.Events()
	assertHasProgress(t, events, "host", appcore.StateRunning)
	assertHasProgress(t, events, "host", appcore.StateCompleted)
	assertHasProgress(t, events, "file_system", appcore.StateSkipped)
	assertHasProgress(t, events, "env_vars", appcore.StateSkipped)
	assertHasProgress(t, events, "web_logs", appcore.StateSkipped)
}

func TestRunLocalScanHonorsHostOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"host"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	if result.Envelope.Sections["system"] == nil {
		t.Fatalf("expected host system section")
	}
	for _, section := range []string{"users", "groups", "processes", "processTree"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in host-only scan", section)
		}
	}
	if got := uploadItemIDs(result); len(got) != 2 || got[0] != "host" || got[1] != "diagnostics" {
		t.Fatalf("expected host and diagnostics upload items, got %#v", got)
	}
}

func assertHasProgress(t *testing.T, events []appcore.StatusEvent, stageKey string, state appcore.StatusState) {
	t.Helper()
	for _, event := range events {
		if event.Type == appcore.EventScanProgress && event.StageKey == stageKey && event.State == state {
			return
		}
	}
	t.Fatalf("missing %s/%s progress in %#v", stageKey, state, events)
}

func TestRunLocalScanHonorsProcessOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"process"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	if result.Envelope.Sections["processes"] == nil || result.Envelope.Sections["processTree"] == nil {
		t.Fatalf("expected process sections")
	}
	if result.Envelope.Sections["processDetails"] == nil {
		t.Fatalf("expected linux process details section")
	}
	if result.Envelope.Sections["fileIdentities"] == nil {
		t.Fatalf("expected process file identities section")
	}
	for _, section := range []string{"users", "groups", "system", "resources", "hardware"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in process-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 2 || got[0] != "process" || got[1] != "file_identity" {
		t.Fatalf("expected process and file identity upload items, got %#v", got)
	}
}

func TestRunLocalScanHonorsNetworkOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"network"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	if result.Envelope.Sections["network"] == nil {
		t.Fatalf("expected network section")
	}
	for _, section := range []string{"users", "groups", "system", "processes", "processTree"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in network-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "network" {
		t.Fatalf("expected only network upload item, got %#v", got)
	}
}

func TestRunLocalScanHonorsStartupOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"startup"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	for _, section := range []string{"services", "timers", "cronJobs", "persistenceItems"} {
		if result.Envelope.Sections[section] == nil {
			t.Fatalf("expected %s section", section)
		}
	}
	for _, section := range []string{"users", "groups", "system", "processes", "processTree", "network"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in startup-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "startup" {
		t.Fatalf("expected only startup upload item, got %#v", got)
	}
}

func TestRunLocalScanHonorsLogsOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"logs"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	for _, section := range []string{"linuxLogSources", "linuxLogEvents"} {
		if result.Envelope.Sections[section] == nil {
			t.Fatalf("expected %s section", section)
		}
	}
	for _, section := range []string{"users", "groups", "system", "processes", "processTree", "network", "services"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in logs-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "logs" {
		t.Fatalf("expected only logs upload item, got %#v", got)
	}
}

func TestRunLocalScanHonorsSoftwareOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"software"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	if result.Envelope.Sections["software"] == nil {
		t.Fatalf("expected software section")
	}
	for _, section := range []string{"users", "groups", "system", "processes", "processTree", "network", "services", "linuxLogEvents"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in software-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "software" {
		t.Fatalf("expected only software upload item, got %#v", got)
	}
}

func TestRunLocalScanHonorsEnvVarsOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"env_vars"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	if result.Envelope.Sections["envVars"] == nil {
		t.Fatalf("expected envVars section")
	}
	for _, section := range []string{"users", "groups", "system", "processes", "processTree", "network", "services", "linuxLogEvents", "software"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in env-vars-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "env_vars" {
		t.Fatalf("expected only env_vars upload item, got %#v", got)
	}
}

func TestRunLocalScanHonorsUserTracesOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"user_traces"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	if result.Envelope.Sections["operationRecords"] == nil {
		t.Fatalf("expected operationRecords section")
	}
	for _, section := range []string{"users", "groups", "system", "processes", "processTree", "network", "services", "linuxLogEvents", "software", "envVars"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in user-traces-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "operation_records" {
		t.Fatalf("expected only operation_records upload item, got %#v", got)
	}
}

func TestRunLocalScanHonorsWebLogsOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"web_logs"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	if result.Envelope.Sections["webLogSources"] == nil {
		t.Fatalf("expected webLogSources section")
	}
	if result.Envelope.Sections["webLogEntries"] == nil {
		t.Fatalf("expected webLogEntries section")
	}
	for _, section := range []string{"users", "groups", "system", "linuxLogSources", "linuxLogEvents", "services"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in web-logs-only scan", section)
		}
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "web_logs" {
		t.Fatalf("expected only web_logs upload item, got %#v", got)
	}
}

func TestRunLocalScanHonorsTimelineOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"timeline"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	events, ok := result.Envelope.Sections["timelineEvents"]
	if !ok {
		t.Fatalf("expected timelineEvents section")
	}
	if got, ok := events.([]contracts.TimelineEvent); !ok || len(got) == 0 {
		t.Fatalf("expected derived timeline events, got %#v", events)
	}
	for _, section := range []string{"users", "groups", "system", "processes", "processTree", "network", "services", "linuxLogEvents"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in timeline-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "timeline" {
		t.Fatalf("expected only timeline upload item, got %#v", got)
	}
}

func TestRunLocalScanAppliesWindowDaysToTimestampedEvidence(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:        filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:      "amd64",
		AgentID:     "agent-linux-1",
		ScanID:      "scan-1",
		ScanScope:   []string{"logs", "web_logs", "user_traces", "timeline"},
		WindowDays:  7,
		CollectedAt: mustParseRunnerTime(t, "2026-05-12T12:00:00Z"),
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}

	logEvents, ok := result.Envelope.Sections["linuxLogEvents"].([]logs.Event)
	if !ok {
		t.Fatalf("expected linuxLogEvents slice, got %#v", result.Envelope.Sections["linuxLogEvents"])
	}
	for _, event := range logEvents {
		if event.Timestamp != "" && event.Timestamp < "2026-05-05T12:00:00Z" {
			t.Fatalf("log event outside 7-day window was kept: %#v", event)
		}
	}
	if findLinuxLogEvent(logEvents, "auth_success") != nil {
		t.Fatalf("untimestamped syslog event should not be kept when a window is active: %#v", logEvents)
	}

	webEntries, ok := result.Envelope.Sections["webLogEntries"].([]weblogs.Entry)
	if !ok || len(webEntries) != 1 {
		t.Fatalf("expected recent web log entry to remain, got %#v", result.Envelope.Sections["webLogEntries"])
	}
	if !mustParseRunnerTime(t, webEntries[0].Timestamp).Equal(mustParseRunnerTime(t, "2026-05-08T02:20:30Z")) {
		t.Fatalf("unexpected web log timestamp: %#v", webEntries[0])
	}

	operationRecords, ok := result.Envelope.Sections["operationRecords"].([]history.OperationRecord)
	if !ok {
		t.Fatalf("expected operationRecords slice, got %#v", result.Envelope.Sections["operationRecords"])
	}
	if len(operationRecords) != 0 {
		t.Fatalf("expected old shell history to be filtered out, got %#v", operationRecords)
	}
}

func TestRunLocalScanHonorsFileSystemOnlyScope(t *testing.T) {
	result, err := RunLocalScan(Config{
		Root:      filepath.Join("..", "collectors", "testdata", "root"),
		GoArch:    "amd64",
		AgentID:   "agent-linux-1",
		ScanID:    "scan-1",
		ScanScope: []string{"file_system"},
	})
	if err != nil {
		t.Fatalf("run local scan: %v", err)
	}
	for _, section := range []string{"forensicVolumes", "forensicDirectoryNodes", "forensicFileEntries", "forensicTimelineEvents"} {
		if result.Envelope.Sections[section] == nil {
			t.Fatalf("expected %s section", section)
		}
	}
	for _, section := range []string{"users", "groups", "system", "processes", "processTree", "network", "services", "linuxLogEvents", "timelineEvents"} {
		if _, exists := result.Envelope.Sections[section]; exists {
			t.Fatalf("did not expect %s section in file-system-only scan", section)
		}
	}
	if result.Envelope.Sections["platform"] != "linux" {
		t.Fatalf("expected platform marker")
	}
	if got := uploadItemIDs(result); len(got) != 1 || got[0] != "file_system" {
		t.Fatalf("expected only file_system upload item, got %#v", got)
	}
}

func uploadItemIDs(result Result) []string {
	ids := make([]string, 0, len(result.UploadItems))
	for _, item := range result.UploadItems {
		ids = append(ids, item.ItemID)
	}
	return ids
}

func findLinuxLogEvent(events []logs.Event, eventType string) *logs.Event {
	for index := range events {
		if events[index].EventType == eventType {
			return &events[index]
		}
	}
	return nil
}

func mustParseRunnerTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}
