//go:build !windows

package scanner

import "windows-host-collector/internal/platform/capabilities"

func defaultScannerPlatformProfile() capabilities.Profile {
	return capabilities.DeriveWindowsProfile(capabilities.WindowsFacts{
		MajorVersion:       10,
		MinorVersion:       0,
		BuildNumber:        19045,
		ProductName:        "Windows test profile",
		Architecture:       "amd64",
		WebView2Runtime:    "120.0.0.0",
		FilesystemTypes:    []string{"NTFS"},
		HasBackupPrivilege: true,
	})
}
