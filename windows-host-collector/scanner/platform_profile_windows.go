//go:build windows

package scanner

import "windows-host-collector/internal/platform/capabilities"

func defaultScannerPlatformProfile() capabilities.Profile {
	return capabilities.DeriveCurrentProfile()
}
