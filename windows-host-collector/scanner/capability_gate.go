package scanner

import (
	"fmt"
	"sort"
	"strings"

	"windows-host-collector/internal/platform/capabilities"
	"windows-host-collector/models"
)

const platformCapabilitiesVersion = "windows-capabilities-v1"

type stageRunDecision struct {
	Run        bool
	Detail     string
	ReasonCode string
	Capability capabilities.Capability
	Evidence   string
}

var stageRequiredCapabilities = map[string][]capabilities.Capability{
	"system":      {capabilities.CapabilityWMI},
	"file_system": {capabilities.CapabilityRawNTFSRead},
	"network":     {capabilities.CapabilityWMI},
	"services":    {capabilities.CapabilityWMI, capabilities.CapabilityRegistry},
	"users":       {capabilities.CapabilityWindowsUserArtifacts},
	"software":    {capabilities.CapabilityRegistry},
	"prefetch":    {capabilities.CapabilityPrefetchWin10Layout},
	"browser_history": {
		capabilities.CapabilityWindowsUserArtifacts,
		capabilities.CapabilityBrowserHistorySQLite,
	},
	"usb":        {capabilities.CapabilityRegistry},
	"registries": {capabilities.CapabilityRegistry},
	"event_logs": {capabilities.CapabilityEventLogAPI},
}

func stageCapabilityDecision(stageKey string, profile capabilities.Profile) stageRunDecision {
	if profile.SupportLevel == capabilities.SupportUnsupported {
		return stageRunDecision{
			Run:        false,
			Detail:     detailWithReason("能力探测跳过", profile.Reason),
			ReasonCode: "unsupported_os",
			Evidence:   diagnosticEvidence(profile),
		}
	}

	required := stageRequiredCapabilities[stageKey]
	missing := profile.Missing(required...)
	if len(missing) == 0 {
		return stageRunDecision{Run: true}
	}

	return stageRunDecision{
		Run:        false,
		Detail:     fmt.Sprintf("能力探测跳过: missing_capabilities=%s", joinCapabilities(missing)),
		ReasonCode: "missing_capability",
		Capability: missing[0],
		Evidence:   capabilityEvidence(profile, missing[0]),
	}
}

func platformProfileModel(profile capabilities.Profile) *models.PlatformProfile {
	capabilityNames := make([]string, 0, len(profile.Capabilities))
	for capability, supported := range profile.Capabilities {
		if supported {
			capabilityNames = append(capabilityNames, string(capability))
		}
	}
	sort.Strings(capabilityNames)

	return &models.PlatformProfile{
		Platform:            profile.Platform,
		SupportLevel:        string(profile.SupportLevel),
		BuildFamily:         profile.BuildFamily,
		Architecture:        profile.Architecture,
		CapabilitiesVersion: platformCapabilitiesVersion,
		Capabilities:        capabilityNames,
		CapabilityStatuses:  capabilityStatusesModel(profile),
		Facts:               platformFactsModel(profile.Facts),
	}
}

func capabilityStatusesModel(profile capabilities.Profile) map[string]any {
	if len(profile.ProbeStatuses) == 0 {
		return nil
	}
	statuses := make(map[string]any, len(profile.ProbeStatuses))
	for capability, status := range profile.ProbeStatuses {
		statuses[string(capability)] = map[string]any{
			"supported": status.Supported,
			"reason":    status.Reason,
			"evidence":  status.Evidence,
		}
	}
	return statuses
}

func platformFactsModel(facts capabilities.WindowsFacts) map[string]any {
	result := map[string]any{
		"osFamily":            string(facts.OSFamily),
		"productName":         facts.ProductName,
		"editionId":           facts.EditionID,
		"installationType":    facts.InstallationType,
		"majorVersion":        facts.MajorVersion,
		"minorVersion":        facts.MinorVersion,
		"buildNumber":         facts.BuildNumber,
		"ubr":                 facts.UBR,
		"architecture":        facts.Architecture,
		"webView2Runtime":     facts.WebView2Runtime,
		"filesystemTypes":     facts.FilesystemTypes,
		"isElevated":          facts.IsElevated,
		"hasBackupPrivilege":  facts.HasBackupPrivilege,
		"hasSeDebugPrivilege": facts.HasSeDebugPrivilege,
	}
	if facts.DomainRole != 0 {
		result["domainRole"] = facts.DomainRole
	}
	return result
}

func stageDiagnostic(stageKey string, decision stageRunDecision) models.StageDiagnostic {
	return models.StageDiagnostic{
		Stage:      stageKey,
		State:      string(models.StageSkipped),
		ReasonCode: decision.ReasonCode,
		Capability: string(decision.Capability),
		Evidence:   decision.Evidence,
	}
}

func diagnosticEvidence(profile capabilities.Profile) string {
	if profile.BuildFamily != "" {
		return profile.BuildFamily
	}
	if profile.Reason != "" {
		return profile.Reason
	}
	return profile.Platform
}

func capabilityEvidence(profile capabilities.Profile, capability capabilities.Capability) string {
	status := profile.CapabilityStatus(capability)
	if status.Evidence == "" && status.Reason == "" {
		return diagnosticEvidence(profile)
	}
	if status.Evidence == "" {
		return status.Reason
	}
	if status.Reason == "" || status.Reason == "available" {
		return status.Evidence
	}
	return status.Evidence + ":" + status.Reason
}

func detailWithReason(prefix, reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "unsupported_os"
	}
	return prefix + ": " + reason
}

func joinCapabilities(values []capabilities.Capability) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, string(value))
	}
	return strings.Join(parts, ",")
}
