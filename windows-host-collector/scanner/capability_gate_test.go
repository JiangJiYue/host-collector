package scanner

import (
	"context"
	"strings"
	"testing"

	"windows-host-collector/internal/platform/capabilities"
	"windows-host-collector/models"
)

func TestStageCapabilityGateSkipsWin7PrefetchAndKeepsEventLogs(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7601,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
	})

	if decision := stageCapabilityDecision("prefetch", profile); decision.Run {
		t.Fatalf("expected Win7 prefetch to be skipped")
	} else if !strings.Contains(decision.Detail, "prefetch_win10_layout") {
		t.Fatalf("expected missing capability in detail, got %q", decision.Detail)
	} else if decision.Evidence != "windows_7_or_server_2008_r2:legacy_prefetch_layout" {
		t.Fatalf("expected structured prefetch evidence, got %#v", decision)
	}

	if decision := stageCapabilityDecision("event_logs", profile); !decision.Run {
		t.Fatalf("expected Win7 event logs to remain enabled, got %q", decision.Detail)
	}
}

func TestStageCapabilityGateUsesRuntimeProbeEvidenceForRawNTFS(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"NTFS"},
		HasBackupPrivilege: false,
	})

	decision := stageCapabilityDecision("file_system", profile)
	if decision.Run {
		t.Fatalf("expected file_system stage to be skipped without backup privilege")
	}
	if decision.ReasonCode != "missing_capability" ||
		decision.Capability != capabilities.CapabilityRawNTFSRead ||
		decision.Evidence != "SeBackupPrivilege:backup_privilege_missing" {
		t.Fatalf("expected raw NTFS runtime evidence, got %#v", decision)
	}
}

func TestStageCapabilityGateUsesRuntimeProbeEvidenceForWMI(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"NTFS"},
		HasBackupPrivilege: true,
		CapabilityProbes: map[capabilities.Capability]capabilities.ProbeStatus{
			capabilities.CapabilityWMI: {
				Supported: false,
				Reason:    "wmi_unavailable",
				Evidence:  "winmgmt_service_stopped",
			},
		},
	})

	decision := stageCapabilityDecision("system", profile)
	if decision.Run {
		t.Fatalf("expected system stage to be skipped when WMI probe is unavailable")
	}
	if decision.ReasonCode != "missing_capability" ||
		decision.Capability != capabilities.CapabilityWMI ||
		decision.Evidence != "winmgmt_service_stopped:wmi_unavailable" {
		t.Fatalf("expected WMI runtime probe evidence, got %#v", decision)
	}
}

func TestStageCapabilityGateSkipsAllCollectionForUnsupportedWindows(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7600,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
	})

	decision := stageCapabilityDecision("system", profile)
	if decision.Run {
		t.Fatalf("expected unsupported Windows profile to skip system collection")
	}
	if !strings.Contains(decision.Detail, "unsupported_os") {
		t.Fatalf("expected unsupported_os detail, got %q", decision.Detail)
	}
}

func TestQuickScannerEmitsPlatformProfileAndCapabilityDiagnostics(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7601,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
	})

	data, err := NewQuickScanner().
		WithScope([]string{"user_traces"}).
		WithPlatformProfile(profile).
		Scan(context.Background())
	if err != nil {
		t.Fatalf("quick scan: %v", err)
	}

	if data.PlatformProfile == nil {
		t.Fatalf("expected platform profile in scan envelope")
	}
	if data.PlatformProfile.SupportLevel != string(capabilities.SupportLegacy) {
		t.Fatalf("expected legacy support level, got %#v", data.PlatformProfile)
	}
	if data.PlatformProfile.BuildFamily != "windows_7_or_server_2008_r2" {
		t.Fatalf("expected Win7 build family, got %#v", data.PlatformProfile)
	}
	status, ok := data.PlatformProfile.CapabilityStatuses[string(capabilities.CapabilityPrefetchWin10Layout)].(map[string]any)
	if !ok {
		t.Fatalf("expected prefetch capability status, got %#v", data.PlatformProfile.CapabilityStatuses)
	}
	if status["supported"] != false || status["reason"] != "legacy_prefetch_layout" {
		t.Fatalf("unexpected prefetch capability status: %#v", status)
	}

	var prefetchDiagnostic *models.StageDiagnostic
	for i := range data.StageDiagnostics {
		if data.StageDiagnostics[i].Stage == "prefetch" {
			prefetchDiagnostic = &data.StageDiagnostics[i]
			break
		}
	}
	if prefetchDiagnostic == nil {
		t.Fatalf("expected prefetch stage diagnostic, got %#v", data.StageDiagnostics)
	}
	if prefetchDiagnostic.State != string(models.StageSkipped) ||
		prefetchDiagnostic.ReasonCode != "missing_capability" ||
		prefetchDiagnostic.Capability != string(capabilities.CapabilityPrefetchWin10Layout) ||
		prefetchDiagnostic.Evidence != "windows_7_or_server_2008_r2:legacy_prefetch_layout" {
		t.Fatalf("unexpected prefetch diagnostic: %#v", prefetchDiagnostic)
	}
}

func TestQuickScannerUsesCapabilityGateForBrowserHistoryOnUnsupportedWindows(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7600,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
	})

	data, err := NewQuickScanner().
		WithScope([]string{"user_traces"}).
		WithPlatformProfile(profile).
		Scan(context.Background())
	if err != nil {
		t.Fatalf("quick scan: %v", err)
	}

	var browserDiagnostic *models.StageDiagnostic
	for i := range data.StageDiagnostics {
		if data.StageDiagnostics[i].Stage == "browser_history" {
			browserDiagnostic = &data.StageDiagnostics[i]
			break
		}
	}
	if browserDiagnostic == nil {
		t.Fatalf("expected browser_history stage diagnostic, got %#v", data.StageDiagnostics)
	}
	if browserDiagnostic.ReasonCode != "unsupported_os" || browserDiagnostic.State != string(models.StageSkipped) {
		t.Fatalf("unexpected browser_history diagnostic: %#v", browserDiagnostic)
	}
}

func TestStageCapabilityGateSkipsBrowserHistoryForLegacyWindowsRuntime(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7601,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
	})

	decision := stageCapabilityDecision("browser_history", profile)
	if decision.Run {
		t.Fatalf("expected browser_history to be skipped for legacy Windows runtime")
	}
	if decision.ReasonCode != "missing_capability" ||
		decision.Capability != capabilities.CapabilityBrowserHistorySQLite ||
		decision.Evidence != "windows_7_or_server_2008_r2:legacy_runtime_sqlite_disabled" {
		t.Fatalf("expected legacy sqlite capability evidence, got %#v", decision)
	}
}
