package capabilities

import (
	"strings"
)

func detectBaseCapabilityProbes(facts WindowsFacts, coreProbes map[Capability]ProbeStatus) map[Capability]ProbeStatus {
	probes := map[Capability]ProbeStatus{}
	for capability, status := range coreProbes {
		probes[capability] = normalizeProbeStatus(status, "probe_failed", "")
	}

	webView2Runtime := strings.TrimSpace(facts.WebView2Runtime)
	if webView2Runtime == "" || strings.EqualFold(webView2Runtime, "not_detected") || strings.EqualFold(webView2Runtime, "unsupported") {
		if webView2Runtime == "" {
			webView2Runtime = "not_detected"
		}
		probes[CapabilityModernDesktopUI] = ProbeStatus{
			Supported: false,
			Reason:    "webview2_runtime_missing",
			Evidence:  webView2Runtime,
		}
	} else {
		probes[CapabilityModernDesktopUI] = ProbeStatus{
			Supported: true,
			Reason:    "available",
			Evidence:  webView2Runtime,
		}
	}

	if len(facts.FilesystemTypes) > 0 && !hasFilesystemType(facts.FilesystemTypes, "NTFS") {
		probes[CapabilityRawNTFSRead] = ProbeStatus{
			Supported: false,
			Reason:    "ntfs_volume_not_detected",
			Evidence:  strings.Join(facts.FilesystemTypes, ","),
		}
	} else if !facts.HasBackupPrivilege {
		probes[CapabilityRawNTFSRead] = ProbeStatus{
			Supported: false,
			Reason:    "backup_privilege_missing",
			Evidence:  "SeBackupPrivilege",
		}
	} else {
		probes[CapabilityRawNTFSRead] = ProbeStatus{
			Supported: true,
			Reason:    "available",
			Evidence:  "SeBackupPrivilege",
		}
	}
	return probes
}

func normalizeProbeStatus(status ProbeStatus, defaultUnsupportedReason string, defaultEvidence string) ProbeStatus {
	reason := strings.TrimSpace(status.Reason)
	if reason == "" {
		if status.Supported {
			reason = "available"
		} else {
			reason = defaultUnsupportedReason
		}
	}
	evidence := strings.TrimSpace(status.Evidence)
	if evidence == "" {
		evidence = defaultEvidence
	}
	return ProbeStatus{
		Supported: status.Supported,
		Reason:    reason,
		Evidence:  evidence,
	}
}
