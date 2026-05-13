package runtimeprofile

import (
	"testing"

	"windows-host-collector/internal/platform/capabilities"
)

func TestSelectModernDesktopWhenModernUIIsAvailable(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"NTFS"},
		IsElevated:         true,
		HasBackupPrivilege: true,
	})

	decision := Select(profile)
	if decision.Runtime != RuntimeModernDesktop || !decision.CanRun {
		t.Fatalf("expected modern desktop decision, got %#v", decision)
	}
}

func TestSelectLegacyUIWhenWebView2IsMissingOnModernWindows(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows 10 Pro",
		Architecture:       "amd64",
		WebView2Runtime:    "not_detected",
		FilesystemTypes:    []string{"NTFS"},
		IsElevated:         true,
		HasBackupPrivilege: true,
	})

	decision := Select(profile)
	if decision.Runtime != RuntimeLegacyUI || !decision.CanRun {
		t.Fatalf("expected legacy UI decision without WebView2, got %#v", decision)
	}
	if decision.Reason != "modern_desktop_ui_unavailable" {
		t.Fatalf("expected WebView2 downgrade reason, got %q", decision.Reason)
	}
}

func TestSelectLegacyUIForWindows7SP1(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion:       6,
		MinorVersion:       1,
		BuildNumber:        7601,
		ProductName:        "Windows 7 Professional",
		Architecture:       "amd64",
		IsElevated:         true,
		HasBackupPrivilege: true,
	})

	decision := Select(profile)
	if decision.Runtime != RuntimeLegacyUI || !decision.CanRun {
		t.Fatalf("expected legacy UI decision for Win7 SP1, got %#v", decision)
	}
}

func TestRejectUnsupportedOSBeforeRuntimeSelection(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion: 6,
		MinorVersion: 1,
		BuildNumber:  7600,
		ProductName:  "Windows 7 Professional",
		Architecture: "amd64",
		IsElevated:   true,
	})

	decision := Select(profile)
	if decision.CanRun || decision.Runtime != RuntimeNone {
		t.Fatalf("expected unsupported OS rejection, got %#v", decision)
	}
	if decision.Reason != "unsupported_os" {
		t.Fatalf("expected unsupported_os reason, got %q", decision.Reason)
	}
}

func TestRejectNonAdministratorBeforeRuntimeSelection(t *testing.T) {
	profile := capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion:    10,
		MinorVersion:    0,
		BuildNumber:     19045,
		ProductName:     "Windows 10 Pro",
		Architecture:    "amd64",
		WebView2Runtime: "120.0.0.0",
		IsElevated:      false,
	})

	decision := Select(profile)
	if decision.CanRun || decision.Runtime != RuntimeNone {
		t.Fatalf("expected administrator rejection, got %#v", decision)
	}
	if decision.Reason != "administrator_required" {
		t.Fatalf("expected administrator_required reason, got %q", decision.Reason)
	}
}
