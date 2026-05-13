package runtimeprofile

import (
	"collector-shared/runtimecheck"
	"windows-host-collector/internal/platform/capabilities"
)

type Runtime string

const (
	RuntimeNone          Runtime = "none"
	RuntimeModernDesktop Runtime = "modern_desktop"
	RuntimeLegacyUI      Runtime = "legacy_ui"
	RuntimeHeadless      Runtime = "headless"
)

type Decision struct {
	Runtime      Runtime
	CanRun       bool
	Reason       string
	SupportLevel capabilities.SupportLevel
	Evidence     string
}

func Select(profile capabilities.Profile) Decision {
	if profile.SupportLevel == capabilities.SupportUnsupported {
		return Decision{
			Runtime:      RuntimeNone,
			CanRun:       false,
			Reason:       "unsupported_os",
			SupportLevel: profile.SupportLevel,
			Evidence:     profile.Reason,
		}
	}

	if !profile.Facts.IsElevated {
		check := runtimecheck.RequireAdministrator(false)
		return Decision{
			Runtime:      RuntimeNone,
			CanRun:       false,
			Reason:       string(check.Reason),
			SupportLevel: profile.SupportLevel,
			Evidence:     check.Evidence,
		}
	}

	if profile.SupportLevel == capabilities.SupportModern &&
		profile.Supports(capabilities.CapabilityModernDesktopUI) {
		return Decision{
			Runtime:      RuntimeModernDesktop,
			CanRun:       true,
			Reason:       "modern_desktop_ui_available",
			SupportLevel: profile.SupportLevel,
			Evidence:     profile.CapabilityStatus(capabilities.CapabilityModernDesktopUI).Evidence,
		}
	}

	if profile.SupportLevel == capabilities.SupportModern {
		return Decision{
			Runtime:      RuntimeLegacyUI,
			CanRun:       true,
			Reason:       "modern_desktop_ui_unavailable",
			SupportLevel: profile.SupportLevel,
			Evidence:     profile.CapabilityStatus(capabilities.CapabilityModernDesktopUI).Reason,
		}
	}

	if profile.SupportLevel == capabilities.SupportLegacy {
		return Decision{
			Runtime:      RuntimeLegacyUI,
			CanRun:       true,
			Reason:       "legacy_support_level",
			SupportLevel: profile.SupportLevel,
			Evidence:     profile.BuildFamily,
		}
	}

	return Decision{
		Runtime:      RuntimeHeadless,
		CanRun:       true,
		Reason:       "runtime_default_headless",
		SupportLevel: profile.SupportLevel,
		Evidence:     profile.BuildFamily,
	}
}
