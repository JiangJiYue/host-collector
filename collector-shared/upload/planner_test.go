package upload

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPlannerBuildsLinuxSemanticUploadItems(t *testing.T) {
	payload := map[string]any{
		"timestamp":          "2026-05-02T12:00:00Z",
		"system":             map[string]any{"hostname": "linux-1"},
		"platformFacts":      map[string]any{"platform": "linux", "architecture": "amd64"},
		"processes":          []any{map[string]any{"pid": 1, "name": "systemd"}},
		"processTree":        []any{map[string]any{"pid": 1}},
		"fileIdentities":     []any{map[string]any{"id": "file-1", "path": "/usr/bin/systemd", "sha256": "sha256-value"}},
		"network":            map[string]any{"sessions": []any{}},
		"linuxLogSources":    []any{map[string]any{"path": "/var/log/auth.log"}},
		"linuxLogEvents":     []any{map[string]any{"eventType": "auth"}},
		"webLogSources":      []any{map[string]any{"path": "/var/log/nginx/access.log"}},
		"webLogEntries":      []any{map[string]any{"clientIp": "127.0.0.1"}},
		"timelineEvents":     []any{map[string]any{"eventType": "process_start"}},
		"platform":           "linux",
		"platformExtensions": map[string]any{"linux": map[string]any{"distroId": "ubuntu"}},
	}

	items, err := PlanItems(payload, Metadata{
		AgentID:     "agent-linux-1",
		ScanID:      "scan-1",
		ScanType:    "policy",
		CollectedAt: "2026-05-02T12:00:00Z",
	}, LinuxPlans())
	if err != nil {
		t.Fatalf("plan linux upload items: %v", err)
	}

	got := itemIDs(items)
	want := []string{"host", "process", "file_identity", "network", "logs", "web_logs", "timeline"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected item ids %v, got %v", want, got)
	}
	if items[0].ItemIndex != 1 || items[0].ItemCount != len(items) {
		t.Fatalf("bad item index/count: %#v", items[0])
	}
	if items[0].AgentID != "agent-linux-1" || items[0].ScanID != "scan-1" || items[0].ScanType != "policy" || items[0].CollectedAt != "2026-05-02T12:00:00Z" {
		t.Fatalf("expected metadata on returned item, got %#v", items[0])
	}
	if items[0].ItemKind != "sectionGroup" {
		t.Fatalf("expected host itemKind sectionGroup, got %q", items[0].ItemKind)
	}
	if items[0].ItemName != "host" {
		t.Fatalf("expected host itemName host, got %q", items[0].ItemName)
	}

	var body map[string]any
	if err := json.Unmarshal(items[0].PayloadJSON, &body); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if body["protocolVersion"] != ProtocolVersionUploadItemsV1 {
		t.Fatalf("expected protocol version, got %#v", body)
	}
	if body["platform"] != "linux" {
		t.Fatalf("expected linux platform in item body, got %#v", body)
	}
	if _, exists := body["tenantId"]; exists {
		t.Fatalf("upload item body must not include tenantId: %#v", body)
	}
	if _, exists := body["ownerUserId"]; exists {
		t.Fatalf("upload item body must not include ownerUserId; owner scope comes from the ingestion token: %#v", body)
	}
	if _, exists := body["packageSha256"]; exists {
		t.Fatalf("legacy package field must not be emitted: %#v", body)
	}
	if body["itemName"] != "host" {
		t.Fatalf("expected body itemName host, got %#v", body["itemName"])
	}
}

func TestPlanLinuxItemsUsesLinuxSemanticPlans(t *testing.T) {
	items, err := PlanLinuxItems(map[string]any{
		"system":             map[string]any{"hostname": "linux-1"},
		"platformFacts":      map[string]any{"platform": "linux"},
		"processes":          []any{map[string]any{"pid": 1}},
		"fileIdentities":     []any{map[string]any{"id": "file-1", "path": "/usr/bin/systemd", "sha256": "sha256-value"}},
		"linuxLogSources":    []any{map[string]any{"path": "/var/log/auth.log"}},
		"linuxLogEvents":     []any{map[string]any{"eventType": "auth"}},
		"timelineEvents":     []any{map[string]any{"eventType": "process_start"}},
		"platform":           "linux",
		"platformExtensions": map[string]any{"linux": map[string]any{"distroId": "ubuntu"}},
	}, Metadata{AgentID: "agent-linux-1", ScanID: "scan-1", ScanType: "policy"})
	if err != nil {
		t.Fatalf("plan linux upload items: %v", err)
	}

	got := itemIDs(items)
	want := []string{"host", "process", "file_identity", "logs", "timeline"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected item ids %v, got %v", want, got)
	}

	var body map[string]any
	if err := json.Unmarshal(items[0].PayloadJSON, &body); err != nil {
		t.Fatalf("decode host item: %v", err)
	}
	if body["platform"] != "linux" {
		t.Fatalf("expected linux platform context, got %#v", body)
	}
	if _, ok := body["platformExtensions"].(map[string]any); !ok {
		t.Fatalf("expected platform extensions in linux item, got %#v", body["platformExtensions"])
	}
}

func TestPlannerSkipsPlansWithoutCollectedSections(t *testing.T) {
	items, err := PlanItems(map[string]any{
		"system": map[string]any{"hostname": "linux-1"},
	}, Metadata{AgentID: "agent-1", ScanID: "scan-1", ScanType: "policy"}, LinuxPlans())
	if err != nil {
		t.Fatalf("plan linux upload items: %v", err)
	}

	got := itemIDs(items)
	want := []string{"host"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected only populated item ids %v, got %v", want, got)
	}
	if items[0].ItemIndex != 1 || items[0].ItemCount != 1 {
		t.Fatalf("bad item index/count for single item: %#v", items[0])
	}
}

func TestLinuxPlansMatchRequiredMatrix(t *testing.T) {
	assertPlans(t, LinuxPlans(), []Plan{
		{ItemID: "host", ItemKind: "sectionGroup", Sections: []string{"system", "resources", "hardware", "platformFacts"}},
		{ItemID: "process", ItemKind: "sectionGroup", Sections: []string{"processes", "processDetails", "processTree"}},
		{ItemID: "file_identity", ItemKind: "section", Sections: []string{"fileIdentities"}},
		{ItemID: "network", ItemKind: "section", Sections: []string{"network"}},
		{ItemID: "startup", ItemKind: "sectionGroup", Sections: []string{"services", "timers", "cronJobs", "persistenceItems"}},
		{ItemID: "users", ItemKind: "sectionGroup", Sections: []string{"users", "groups", "privilegeEvidence"}},
		{ItemID: "env_vars", ItemKind: "section", Sections: []string{"envVars"}},
		{ItemID: "software", ItemKind: "section", Sections: []string{"software"}},
		{ItemID: "operation_records", ItemKind: "section", Sections: []string{"operationRecords"}},
		{ItemID: "logs", ItemKind: "sectionGroup", Sections: []string{"linuxLogSources", "linuxLogEvents"}},
		{ItemID: "web_logs", ItemKind: "sectionGroup", Sections: []string{"webLogSources", "webLogEntries"}},
		{ItemID: "file_system", ItemKind: "sectionGroup", Sections: []string{"forensicVolumes", "forensicDirectoryNodes", "forensicFileEntries", "forensicTimelineEvents"}},
		{ItemID: "timeline", ItemKind: "section", Sections: []string{"timelineEvents"}},
		{ItemID: "diagnostics", ItemKind: "sectionGroup", Sections: []string{"platformProfile", "stageDiagnostics"}},
	})
}

func TestPlannerRejectsLegacyPackageFields(t *testing.T) {
	_, err := PlanItems(map[string]any{
		"system":        map[string]any{"hostname": "linux-1"},
		"packageSha256": "legacy",
	}, Metadata{AgentID: "agent-1", ScanID: "scan-1", ScanType: "policy"}, LinuxPlans())
	if err == nil {
		t.Fatalf("expected legacy package field error")
	}
	if !strings.Contains(err.Error(), "packageSha256") {
		t.Fatalf("expected error to mention legacy field, got %v", err)
	}
}

func TestPlannerCoversWindowsCompatiblePlanWithoutWindowsImports(t *testing.T) {
	payload := map[string]any{
		"system":           map[string]any{},
		"resources":        map[string]any{},
		"hardware":         map[string]any{},
		"processes":        []any{},
		"processDetails":   map[string]any{},
		"windowsEventLogs": []any{},
		"platform":         "windows",
		"supportLevel":     "legacy",
		"capabilities":     []any{"event_log_api", "registry", "wmi"},
	}

	items, err := PlanItems(payload, Metadata{AgentID: "agent-1", ScanID: "scan-1", ScanType: "policy"}, WindowsCompatiblePlans())
	if err != nil {
		t.Fatalf("plan windows compatible items: %v", err)
	}
	got := itemIDs(items)
	want := []string{"host", "process", "windows_event_logs"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("expected item ids %v, got %v", want, got)
	}

	var body map[string]any
	if err := json.Unmarshal(items[0].PayloadJSON, &body); err != nil {
		t.Fatalf("decode windows item: %v", err)
	}
	if body["platform"] != "windows" || body["supportLevel"] != "legacy" {
		t.Fatalf("expected windows platform context in shared item body, got %#v", body)
	}
	if _, ok := body["capabilities"].([]any); !ok {
		t.Fatalf("expected capabilities in shared item body, got %#v", body["capabilities"])
	}
}

func TestPlanWindowsItemsExtractsPlatformProfileContext(t *testing.T) {
	payload := map[string]any{
		"system": map[string]any{"hostname": "agent-001"},
		"platformProfile": map[string]any{
			"platform":            "windows",
			"supportLevel":        "legacy",
			"capabilitiesVersion": "windows-capabilities-v1",
			"capabilities": map[string]any{
				"registry":              true,
				"wmi":                   true,
				"event_log_api":         true,
				"prefetch_win10_layout": false,
			},
		},
	}

	items, err := PlanWindowsItems(payload, Metadata{
		AgentID:     "agent-001",
		ScanID:      "scan-001",
		ScanType:    "policy",
		CollectedAt: "2026-05-01T04:32:52Z",
	})
	if err != nil {
		t.Fatalf("plan windows upload items: %v", err)
	}
	if len(items) == 0 || items[0].ItemID != "host" {
		t.Fatalf("expected first item to be host, got %#v", items)
	}

	var body map[string]any
	if err := json.Unmarshal(items[0].PayloadJSON, &body); err != nil {
		t.Fatalf("decode host item: %v", err)
	}
	if body["platform"] != "windows" || body["supportLevel"] != "legacy" || body["capabilitiesVersion"] != "windows-capabilities-v1" {
		t.Fatalf("expected platform profile context in host item, got %#v", body)
	}
	capabilities, ok := body["capabilities"].([]any)
	if !ok {
		t.Fatalf("expected capabilities array in host item, got %#v", body["capabilities"])
	}
	if strings.Join(stringItems(capabilities), ",") != "event_log_api,registry,wmi" {
		t.Fatalf("expected sorted supported capabilities, got %#v", capabilities)
	}
}

func TestPlanWindowsItemsIncludesFileIdentities(t *testing.T) {
	payload := map[string]any{
		"system": map[string]any{"hostname": "agent-001"},
		"fileIdentities": []any{map[string]any{
			"id":     "file-id-1",
			"path":   `C:\Users\Public\svchost.exe`,
			"sha256": "sha256-value",
		}},
		"platform": "windows",
	}

	items, err := PlanWindowsItems(payload, Metadata{
		AgentID:  "agent-001",
		ScanID:   "scan-001",
		ScanType: "policy",
	})
	if err != nil {
		t.Fatalf("plan windows upload items: %v", err)
	}

	var fileIdentityItem *Item
	for i := range items {
		if items[i].ItemID == "file_identity" {
			fileIdentityItem = &items[i]
			break
		}
	}
	if fileIdentityItem == nil {
		t.Fatalf("expected file_identity item, got %v", itemIDs(items))
	}

	var body map[string]any
	if err := json.Unmarshal(fileIdentityItem.PayloadJSON, &body); err != nil {
		t.Fatalf("decode file identity item: %v", err)
	}
	sections, ok := body["sections"].(map[string]any)
	if !ok {
		t.Fatalf("expected sections object, got %#v", body["sections"])
	}
	rows, ok := sections["fileIdentities"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("expected one fileIdentities row, got %#v", sections["fileIdentities"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok || row["sha256"] != "sha256-value" {
		t.Fatalf("expected file identity row to be preserved, got %#v", rows[0])
	}
}

func TestPlanWindowsItemsRejectsLegacyLogsKey(t *testing.T) {
	_, err := PlanWindowsItems(map[string]any{
		"system": map[string]any{"hostname": "agent-001"},
		"logs":   []any{map[string]any{"id": "log-1"}},
	}, Metadata{AgentID: "agent-001", ScanID: "scan-001", ScanType: "policy"})
	if err == nil {
		t.Fatalf("expected legacy logs key error")
	}
	if !strings.Contains(err.Error(), "logs") || !strings.Contains(err.Error(), "windowsEventLogs") {
		t.Fatalf("expected error to mention logs and windowsEventLogs, got %v", err)
	}
}

func TestWindowsCompatiblePlansMatchRequiredMatrix(t *testing.T) {
	assertPlans(t, WindowsCompatiblePlans(), []Plan{
		{ItemID: "host", ItemKind: "sectionGroup", Sections: []string{"system", "resources", "hardware"}},
		{ItemID: "process", ItemKind: "sectionGroup", Sections: []string{"processes", "processDetails"}},
		{ItemID: "file_identity", ItemKind: "section", Sections: []string{"fileIdentities"}},
		{ItemID: "network", ItemKind: "section", Sections: []string{"network"}},
		{ItemID: "startup", ItemKind: "sectionGroup", Sections: []string{"services"}},
		{ItemID: "users", ItemKind: "sectionGroup", Sections: []string{"users"}},
		{ItemID: "env_vars", ItemKind: "section", Sections: []string{"envVars"}},
		{ItemID: "software", ItemKind: "section", Sections: []string{"software"}},
		{ItemID: "prefetch", ItemKind: "section", Sections: []string{"prefetch"}},
		{ItemID: "browser_history", ItemKind: "section", Sections: []string{"browserHistory"}},
		{ItemID: "web_logs", ItemKind: "sectionGroup", Sections: []string{"webLogSources", "webLogEntries"}},
		{ItemID: "usb_records", ItemKind: "section", Sections: []string{"usbRecords"}},
		{ItemID: "operation_records", ItemKind: "section", Sections: []string{"operationRecords"}},
		{ItemID: "registry", ItemKind: "section", Sections: []string{"registries"}},
		{ItemID: "windows_event_logs", ItemKind: "section", Sections: []string{"windowsEventLogs"}},
		{ItemID: "file_system", ItemKind: "sectionGroup", Sections: []string{"forensicVolumes", "forensicDirectoryNodes", "forensicFileEntries", "forensicTimelineEvents", "forensicDiagnostics"}},
		{ItemID: "diagnostics", ItemKind: "sectionGroup", Sections: []string{"platformProfile", "stageDiagnostics"}},
	})
}

func TestUploadPlansKeepPlatformSpecificItemsSeparate(t *testing.T) {
	windowsItems := planIDs(WindowsCompatiblePlans())
	linuxItems := planIDs(LinuxPlans())

	if !containsPlan(windowsItems, "registry") {
		t.Fatalf("expected windows registry plan, got %v", windowsItems)
	}
	if containsPlan(linuxItems, "registry") {
		t.Fatalf("linux plans must not include windows registry item: %v", linuxItems)
	}
	if !containsPlan(windowsItems, "windows_event_logs") {
		t.Fatalf("expected windows event log plan, got %v", windowsItems)
	}
	if containsPlan(linuxItems, "windows_event_logs") {
		t.Fatalf("linux plans must not include windows event log item: %v", linuxItems)
	}
	if !containsPlan(linuxItems, "logs") {
		t.Fatalf("expected linux logs plan, got %v", linuxItems)
	}
	if containsPlan(windowsItems, "logs") {
		t.Fatalf("windows plans must use windows_event_logs, not linux logs: %v", windowsItems)
	}
	if !containsPlan(linuxItems, "software") || !containsPlan(windowsItems, "software") {
		t.Fatalf("expected shared software upload item for both platforms, windows=%v linux=%v", windowsItems, linuxItems)
	}
	if !containsPlan(linuxItems, "env_vars") || !containsPlan(windowsItems, "env_vars") {
		t.Fatalf("expected shared environment variable upload item for both platforms, windows=%v linux=%v", windowsItems, linuxItems)
	}
	if !containsPlan(linuxItems, "operation_records") || !containsPlan(windowsItems, "operation_records") {
		t.Fatalf("expected shared operation records upload item for both platforms, windows=%v linux=%v", windowsItems, linuxItems)
	}
}

func TestPlannerTrimsCollectedAtInPayload(t *testing.T) {
	items, err := PlanItems(map[string]any{
		"system": map[string]any{"hostname": "linux-1"},
	}, Metadata{AgentID: "agent-1", ScanID: "scan-1", ScanType: "policy", CollectedAt: " 2026-05-02T12:00:00Z "}, LinuxPlans())
	if err != nil {
		t.Fatalf("plan linux upload items: %v", err)
	}

	var body map[string]any
	if err := json.Unmarshal(items[0].PayloadJSON, &body); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if body["collectedAt"] != "2026-05-02T12:00:00Z" {
		t.Fatalf("expected trimmed collectedAt in payload, got %#v", body["collectedAt"])
	}
}

func TestNormalizeMetadataTrimsFieldsAndAppliesDefaultScanType(t *testing.T) {
	got := NormalizeMetadata(Metadata{
		AgentID:     " agent-1 ",
		ScanID:      " scan-1 ",
		ScanType:    " ",
		CollectedAt: " 2026-05-07T12:00:00Z ",
	}, "quick")
	if got.AgentID != "agent-1" || got.ScanID != "scan-1" || got.ScanType != "quick" || got.CollectedAt != "2026-05-07T12:00:00Z" {
		t.Fatalf("metadata was not normalized: %#v", got)
	}
}

func itemIDs(items []Item) []string {
	got := make([]string, 0, len(items))
	for _, item := range items {
		got = append(got, item.ItemID)
	}
	return got
}

func stringItems(items []any) []string {
	values := make([]string, 0, len(items))
	for _, item := range items {
		if value, ok := item.(string); ok {
			values = append(values, value)
		}
	}
	return values
}

func planIDs(plans []Plan) []string {
	values := make([]string, 0, len(plans))
	for _, plan := range plans {
		values = append(values, plan.ItemID)
	}
	return values
}

func containsPlan(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertPlans(t *testing.T, got []Plan, want []Plan) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("expected %d plans, got %d: %#v", len(want), len(got), got)
	}
	for i := range want {
		if got[i].ItemID != want[i].ItemID {
			t.Fatalf("plan %d expected item id %q, got %q", i, want[i].ItemID, got[i].ItemID)
		}
		if got[i].ItemKind != want[i].ItemKind {
			t.Fatalf("plan %s expected item kind %q, got %q", want[i].ItemID, want[i].ItemKind, got[i].ItemKind)
		}
		if strings.Join(got[i].Sections, ",") != strings.Join(want[i].Sections, ",") {
			t.Fatalf("plan %s expected sections %v, got %v", want[i].ItemID, want[i].Sections, got[i].Sections)
		}
	}
}
