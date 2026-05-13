package capabilities

import (
	"testing"

	"collector-shared/contracts"
)

func TestWindowsCapabilitiesUseSharedContractTypes(t *testing.T) {
	var capability Capability = contracts.CapabilityWindowsWMI
	var support SupportLevel = contracts.SupportModern

	if capability != CapabilityWMI {
		t.Fatalf("expected Windows WMI capability to use shared contract value, got %q", capability)
	}
	if support != SupportModern {
		t.Fatalf("expected support level to use shared contract value, got %q", support)
	}
}

func TestWindows7SP1IsLegacyAndDisablesModernCollectors(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7601,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
	})

	if profile.SupportLevel != SupportLegacy {
		t.Fatalf("expected Windows 7 SP1 to be legacy support, got %q", profile.SupportLevel)
	}
	for _, capability := range []Capability{
		CapabilityModernDesktopUI,
		CapabilityPrefetchWin10Layout,
		CapabilityProcessHandleDetail,
		CapabilityBrowserHistorySQLite,
	} {
		if profile.Supports(capability) {
			t.Fatalf("expected Windows 7 SP1 to disable %s", capability)
		}
	}
	if !profile.Supports(CapabilityEventLogAPI) {
		t.Fatalf("expected Windows 7 SP1 to keep event log API capability")
	}
}

func TestWindows7SP1RecordsStructuredCapabilityProbeStatus(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7601,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
	})

	prefetch := profile.CapabilityStatus(CapabilityPrefetchWin10Layout)
	if prefetch.Supported {
		t.Fatalf("expected Win7 SP1 prefetch probe to be unsupported")
	}
	if prefetch.Reason != "legacy_prefetch_layout" {
		t.Fatalf("expected legacy prefetch reason, got %#v", prefetch)
	}
	if prefetch.Evidence != "windows_7_or_server_2008_r2" {
		t.Fatalf("expected build-family evidence, got %#v", prefetch)
	}

	eventLog := profile.CapabilityStatus(CapabilityEventLogAPI)
	if !eventLog.Supported || eventLog.Reason != "available" {
		t.Fatalf("expected event log probe to be available, got %#v", eventLog)
	}
}

func TestWindows10EnablesModernCollectors(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"NTFS"},
		HasBackupPrivilege: true,
	})

	if profile.SupportLevel != SupportModern {
		t.Fatalf("expected Windows 10 to be modern support, got %q", profile.SupportLevel)
	}
	for _, capability := range []Capability{
		CapabilityModernDesktopUI,
		CapabilityPrefetchWin10Layout,
		CapabilityProcessHandleDetail,
		CapabilityRawNTFSRead,
	} {
		if !profile.Supports(capability) {
			t.Fatalf("expected Windows 10 to support %s", capability)
		}
	}
}

func TestWindows10WithoutWebView2DowngradesDesktopUICapability(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "not_detected",
		FilesystemTypes:    []string{"NTFS"},
		HasBackupPrivilege: true,
	})

	if profile.SupportLevel != SupportModern {
		t.Fatalf("expected Windows 10 to remain modern support, got %q", profile.SupportLevel)
	}
	status := profile.CapabilityStatus(CapabilityModernDesktopUI)
	if status.Supported {
		t.Fatalf("expected modern desktop UI to be disabled without WebView2 runtime, got %#v", status)
	}
	if status.Reason != "webview2_runtime_missing" || status.Evidence != "not_detected" {
		t.Fatalf("expected WebView2 runtime evidence, got %#v", status)
	}
}

func TestRawNTFSReadRequiresNTFSAndBackupPrivilege(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"ReFS"},
		HasBackupPrivilege: true,
	})
	status := profile.CapabilityStatus(CapabilityRawNTFSRead)
	if status.Supported {
		t.Fatalf("expected raw NTFS read to be disabled when no NTFS volume is detected, got %#v", status)
	}
	if status.Reason != "ntfs_volume_not_detected" || status.Evidence != "ReFS" {
		t.Fatalf("expected filesystem evidence, got %#v", status)
	}

	profile = DeriveWindowsProfile(WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"NTFS"},
		HasBackupPrivilege: false,
	})
	status = profile.CapabilityStatus(CapabilityRawNTFSRead)
	if status.Supported {
		t.Fatalf("expected raw NTFS read to be disabled without backup privilege, got %#v", status)
	}
	if status.Reason != "backup_privilege_missing" || status.Evidence != "SeBackupPrivilege" {
		t.Fatalf("expected privilege evidence, got %#v", status)
	}
}

func TestCoreCapabilityProbesOverrideBaseWindowsCapabilities(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"NTFS"},
		HasBackupPrivilege: true,
		CapabilityProbes: map[Capability]ProbeStatus{
			CapabilityWMI: {
				Supported: false,
				Reason:    "wmi_unavailable",
				Evidence:  "winmgmt_service_stopped",
			},
			CapabilityEventLogAPI: {
				Supported: false,
				Reason:    "permission_denied",
				Evidence:  "Security",
			},
			CapabilityRegistry: {
				Supported: false,
				Reason:    "registry_view_unavailable",
				Evidence:  "HKLM64",
			},
		},
	})

	for capability, expected := range map[Capability]ProbeStatus{
		CapabilityWMI:         {Supported: false, Reason: "wmi_unavailable", Evidence: "winmgmt_service_stopped"},
		CapabilityEventLogAPI: {Supported: false, Reason: "permission_denied", Evidence: "Security"},
		CapabilityRegistry:    {Supported: false, Reason: "registry_view_unavailable", Evidence: "HKLM64"},
	} {
		if profile.Supports(capability) {
			t.Fatalf("expected %s to be disabled by runtime probe", capability)
		}
		if status := profile.CapabilityStatus(capability); status != expected {
			t.Fatalf("unexpected %s status: got %#v want %#v", capability, status, expected)
		}
	}
}

func TestDetectBaseCapabilityProbesAddsCoreProbeResults(t *testing.T) {
	facts := WindowsFacts{
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"NTFS"},
		HasBackupPrivilege: true,
	}

	probes := detectBaseCapabilityProbes(facts, map[Capability]ProbeStatus{
		CapabilityWMI:         {Supported: false, Reason: "wmi_unavailable", Evidence: "winmgmt_service_stopped"},
		CapabilityEventLogAPI: {Supported: false, Reason: "permission_denied", Evidence: "Security"},
		CapabilityRegistry:    {Supported: true, Reason: "available", Evidence: "HKLM"},
	})

	for capability, expected := range map[Capability]ProbeStatus{
		CapabilityModernDesktopUI: {Supported: true, Reason: "available", Evidence: "120.0.0.0"},
		CapabilityRawNTFSRead:     {Supported: true, Reason: "available", Evidence: "SeBackupPrivilege"},
		CapabilityWMI:             {Supported: false, Reason: "wmi_unavailable", Evidence: "winmgmt_service_stopped"},
		CapabilityEventLogAPI:     {Supported: false, Reason: "permission_denied", Evidence: "Security"},
		CapabilityRegistry:        {Supported: true, Reason: "available", Evidence: "HKLM"},
	} {
		if probes[capability] != expected {
			t.Fatalf("unexpected %s probe: got %#v want %#v", capability, probes[capability], expected)
		}
	}
}

func TestUnsupportedWindowsRTMIsRejected(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7600,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
	})

	if profile.SupportLevel != SupportUnsupported {
		t.Fatalf("expected Windows 7 RTM to be unsupported, got %q", profile.SupportLevel)
	}
	if profile.Supports(CapabilityEventLogAPI) {
		t.Fatalf("unsupported Windows builds must not advertise collection capabilities")
	}
}

func TestDeriveWindowsProfilePreservesDetailedFactsAndServerFamily(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        20348,
		UBR:                2402,
		ProductName:        "Windows Server 2022 Datacenter",
		EditionID:          "ServerDatacenter",
		InstallationType:   "Server Core",
		Architecture:       "amd64",
		DomainRole:         3,
		WebView2Runtime:    "unsupported",
		FilesystemTypes:    []string{"NTFS", "ReFS"},
		IsElevated:         true,
		HasBackupPrivilege: true,
	})

	if profile.Facts.OSFamily != OSFamilyServer {
		t.Fatalf("expected server OS family, got %#v", profile.Facts)
	}
	if profile.Facts.EditionID != "ServerDatacenter" || profile.Facts.InstallationType != "Server Core" {
		t.Fatalf("expected edition and installation type to be preserved, got %#v", profile.Facts)
	}
	if profile.Facts.UBR != 2402 || profile.Facts.WebView2Runtime != "unsupported" {
		t.Fatalf("expected UBR and WebView2 runtime facts, got %#v", profile.Facts)
	}
	if !profile.Facts.IsElevated || !profile.Facts.HasBackupPrivilege {
		t.Fatalf("expected privilege facts to be preserved, got %#v", profile.Facts)
	}
}

func TestDeriveWindowsProfileMarksDomainControllerFamily(t *testing.T) {
	profile := DeriveWindowsProfile(WindowsFacts{
		MajorVersion: 10,
		MinorVersion: 0,
		BuildNumber:  17763,
		ProductName:  "Windows Server 2019 Datacenter",
		EditionID:    "ServerDatacenter",
		Architecture: "amd64",
		DomainRole:   5,
	})

	if profile.Facts.OSFamily != OSFamilyDomainController {
		t.Fatalf("expected domain controller OS family, got %#v", profile.Facts)
	}
}
