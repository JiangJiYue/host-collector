package capabilities

import (
	"fmt"
	"runtime"
	"strings"

	"collector-shared/contracts"
)

type Capability = contracts.Capability

const (
	CapabilityModernDesktopUI      = contracts.CapabilityModernDesktopUI
	CapabilityWMI                  = contracts.CapabilityWindowsWMI
	CapabilityEventLogAPI          = contracts.CapabilityWindowsEventLogs
	CapabilityRegistry             = contracts.CapabilityWindowsRegistry
	CapabilityRawNTFSRead          = contracts.CapabilityRawNTFSRead
	CapabilityPrefetchWin10Layout  = contracts.CapabilityPrefetchWin10Layout
	CapabilityProcessHandleDetail  = contracts.CapabilityProcessHandleDetail
	CapabilityWindowsUserArtifacts = contracts.CapabilityWindowsUserArtifacts
	CapabilityBrowserHistorySQLite = contracts.CapabilityBrowserHistorySQLite
)

type SupportLevel = contracts.SupportLevel

const (
	SupportModern      = contracts.SupportModern
	SupportLegacy      = contracts.SupportLegacy
	SupportUnsupported = contracts.SupportUnsupported
)

type OSFamily string

const (
	OSFamilyWorkstation      OSFamily = "workstation"
	OSFamilyServer           OSFamily = "server"
	OSFamilyDomainController OSFamily = "domain_controller"
)

type WindowsFacts struct {
	MajorVersion        int
	MinorVersion        int
	BuildNumber         int
	UBR                 int
	ProductName         string
	EditionID           string
	InstallationType    string
	Architecture        string
	OSFamily            OSFamily
	DomainRole          int
	WebView2Runtime     string
	FilesystemTypes     []string
	IsElevated          bool
	HasBackupPrivilege  bool
	HasSeDebugPrivilege bool
	CapabilityProbes    map[Capability]ProbeStatus
}

type ProbeStatus struct {
	Supported bool
	Reason    string
	Evidence  string
}

type Profile struct {
	Platform      string
	SupportLevel  SupportLevel
	Facts         WindowsFacts
	Capabilities  map[Capability]bool
	ProbeStatuses map[Capability]ProbeStatus
	Reason        string
	BuildFamily   string
	Architecture  string
	ExecutionHint string
}

func (p Profile) Supports(capability Capability) bool {
	return p.Capabilities[capability]
}

func (p Profile) CapabilityStatus(capability Capability) ProbeStatus {
	if status, ok := p.ProbeStatuses[capability]; ok {
		return status
	}
	if p.Supports(capability) {
		return ProbeStatus{Supported: true, Reason: "available", Evidence: p.BuildFamily}
	}
	return ProbeStatus{Supported: false, Reason: "missing_capability", Evidence: p.BuildFamily}
}

func (p Profile) Missing(capabilities ...Capability) []Capability {
	missing := make([]Capability, 0, len(capabilities))
	for _, capability := range capabilities {
		if !p.Supports(capability) {
			missing = append(missing, capability)
		}
	}
	return missing
}

func DeriveCurrentProfile() Profile {
	if runtime.GOOS != "windows" {
		return Profile{
			Platform:      runtime.GOOS,
			SupportLevel:  SupportUnsupported,
			Reason:        "unsupported_platform",
			Architecture:  runtime.GOARCH,
			Capabilities:  map[Capability]bool{},
			ProbeStatuses: map[Capability]ProbeStatus{},
		}
	}
	return DeriveWindowsProfile(DetectWindowsFacts())
}

func DeriveWindowsProfile(facts WindowsFacts) Profile {
	facts.Architecture = strings.TrimSpace(facts.Architecture)
	if facts.Architecture == "" {
		facts.Architecture = runtime.GOARCH
	}
	if facts.OSFamily == "" {
		facts.OSFamily = deriveOSFamily(facts)
	}

	profile := Profile{
		Platform:      "windows",
		Facts:         facts,
		BuildFamily:   windowsBuildFamily(facts),
		Architecture:  facts.Architecture,
		Capabilities:  map[Capability]bool{},
		ProbeStatuses: map[Capability]ProbeStatus{},
	}

	if facts.MajorVersion == 6 && facts.MinorVersion == 1 && facts.BuildNumber < 7601 {
		profile.SupportLevel = SupportUnsupported
		profile.Reason = "unsupported_os: windows_7_requires_sp1"
		return profile
	}
	if facts.MajorVersion < 6 || (facts.MajorVersion == 6 && facts.MinorVersion == 0) {
		profile.SupportLevel = SupportUnsupported
		profile.Reason = "unsupported_os: windows_vista_or_older"
		return profile
	}

	enableBaseWindowsCapabilities(&profile)
	applyRuntimeCapabilityFacts(&profile)

	if facts.MajorVersion > 10 || (facts.MajorVersion == 10 && facts.BuildNumber >= 10240) {
		profile.SupportLevel = SupportModern
		profile.ExecutionHint = "desktop_ui"
		enableModernWindowsCapabilities(&profile)
		applyRuntimeCapabilityFacts(&profile)
		return profile
	}

	if facts.MajorVersion == 6 {
		profile.SupportLevel = SupportLegacy
		profile.ExecutionHint = "collector_core"
		profile.Reason = "legacy_os: prefer headless collector and capability downgrade"
		disableModernWindowsCapabilities(&profile)
		applyRuntimeCapabilityFacts(&profile)
		return profile
	}

	profile.SupportLevel = SupportUnsupported
	profile.Reason = fmt.Sprintf("unsupported_os: windows_%d_%d_build_%d", facts.MajorVersion, facts.MinorVersion, facts.BuildNumber)
	profile.Capabilities = map[Capability]bool{}
	return profile
}

func deriveOSFamily(facts WindowsFacts) OSFamily {
	if facts.DomainRole == 4 || facts.DomainRole == 5 {
		return OSFamilyDomainController
	}
	edition := strings.ToLower(strings.TrimSpace(facts.EditionID))
	installationType := strings.ToLower(strings.TrimSpace(facts.InstallationType))
	productName := strings.ToLower(strings.TrimSpace(facts.ProductName))
	if strings.Contains(edition, "server") ||
		strings.Contains(installationType, "server") ||
		strings.Contains(productName, "server") {
		return OSFamilyServer
	}
	return OSFamilyWorkstation
}

func enableBaseWindowsCapabilities(profile *Profile) {
	setCapabilityStatus(profile, CapabilityWMI, true, "available")
	setCapabilityStatus(profile, CapabilityEventLogAPI, true, "available")
	setCapabilityStatus(profile, CapabilityRegistry, true, "available")
	setCapabilityStatus(profile, CapabilityRawNTFSRead, true, "available")
	setCapabilityStatus(profile, CapabilityWindowsUserArtifacts, true, "available")
	setCapabilityStatus(profile, CapabilityBrowserHistorySQLite, true, "available")
}

func enableModernWindowsCapabilities(profile *Profile) {
	setCapabilityStatus(profile, CapabilityModernDesktopUI, true, "available")
	setCapabilityStatus(profile, CapabilityPrefetchWin10Layout, true, "available")
	setCapabilityStatus(profile, CapabilityProcessHandleDetail, true, "available")
}

func disableModernWindowsCapabilities(profile *Profile) {
	setCapabilityStatus(profile, CapabilityModernDesktopUI, false, "legacy_webview2_not_default")
	setCapabilityStatus(profile, CapabilityPrefetchWin10Layout, false, "legacy_prefetch_layout")
	setCapabilityStatus(profile, CapabilityProcessHandleDetail, false, "legacy_handle_detail_disabled")
	setCapabilityStatus(profile, CapabilityBrowserHistorySQLite, false, "legacy_runtime_sqlite_disabled")
}

func applyRuntimeCapabilityFacts(profile *Profile) {
	applyCapabilityProbeFacts(profile)
	applyWebView2RuntimeFact(profile)
	applyRawNTFSRuntimeFacts(profile)
}

func applyCapabilityProbeFacts(profile *Profile) {
	for capability, status := range profile.Facts.CapabilityProbes {
		if _, ok := profile.Capabilities[capability]; !ok {
			continue
		}
		reason := strings.TrimSpace(status.Reason)
		if reason == "" {
			if status.Supported {
				reason = "available"
			} else {
				reason = "probe_failed"
			}
		}
		evidence := strings.TrimSpace(status.Evidence)
		if evidence == "" {
			evidence = profile.BuildFamily
		}
		setCapabilityStatusWithEvidence(profile, capability, status.Supported, reason, evidence)
	}
}

func applyWebView2RuntimeFact(profile *Profile) {
	if !profile.Supports(CapabilityModernDesktopUI) {
		return
	}
	runtimeVersion := strings.TrimSpace(profile.Facts.WebView2Runtime)
	if runtimeVersion == "" || strings.EqualFold(runtimeVersion, "not_detected") || strings.EqualFold(runtimeVersion, "unsupported") {
		if runtimeVersion == "" {
			runtimeVersion = "not_detected"
		}
		setCapabilityStatusWithEvidence(profile, CapabilityModernDesktopUI, false, "webview2_runtime_missing", runtimeVersion)
	}
}

func applyRawNTFSRuntimeFacts(profile *Profile) {
	if !profile.Supports(CapabilityRawNTFSRead) {
		return
	}
	if len(profile.Facts.FilesystemTypes) > 0 && !hasFilesystemType(profile.Facts.FilesystemTypes, "NTFS") {
		setCapabilityStatusWithEvidence(
			profile,
			CapabilityRawNTFSRead,
			false,
			"ntfs_volume_not_detected",
			strings.Join(profile.Facts.FilesystemTypes, ","),
		)
		return
	}
	if !profile.Facts.HasBackupPrivilege {
		setCapabilityStatusWithEvidence(profile, CapabilityRawNTFSRead, false, "backup_privilege_missing", "SeBackupPrivilege")
	}
}

func hasFilesystemType(values []string, target string) bool {
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			return true
		}
	}
	return false
}

func setCapabilityStatus(profile *Profile, capability Capability, supported bool, reason string) {
	setCapabilityStatusWithEvidence(profile, capability, supported, reason, profile.BuildFamily)
}

func setCapabilityStatusWithEvidence(profile *Profile, capability Capability, supported bool, reason string, evidence string) {
	profile.Capabilities[capability] = supported
	profile.ProbeStatuses[capability] = ProbeStatus{
		Supported: supported,
		Reason:    reason,
		Evidence:  evidence,
	}
}

func windowsBuildFamily(facts WindowsFacts) string {
	switch {
	case facts.MajorVersion == 6 && facts.MinorVersion == 1:
		return "windows_7_or_server_2008_r2"
	case facts.MajorVersion == 6 && facts.MinorVersion == 2:
		return "windows_8_or_server_2012"
	case facts.MajorVersion == 6 && facts.MinorVersion == 3:
		return "windows_8_1_or_server_2012_r2"
	case facts.MajorVersion == 10 && facts.BuildNumber >= 22000:
		return "windows_11_or_server_2025"
	case facts.MajorVersion == 10:
		return "windows_10_or_server_2016_plus"
	default:
		return "unknown_windows"
	}
}
